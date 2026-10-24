// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s09 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s09

import (
	q5 "fmt"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

type BuildError struct{ Issues []ValidationIssue }

func (e *BuildError) Unwrap() error { return q4.ErrInvalidValue }
func (e *BuildError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "LPPa build failed"
	}
	return q5.Sprintf("LPPa build at %s: structural issue %d (IE %d)", e.Issues[0].Location.Path, e.Issues[0].Code, e.Issues[0].IEID)
}
func BridgeBuildBlockingIssues(report ValidationReport) []ValidationIssue {
	blocking := report.Issues[:0]
	for _, issue := range report.Issues {
		if report.budget != nil {
			if err := q4.NewBudgetBuffer(report.budget).ChargeWork(1); err != nil {
				return nil
			}
		}
		if issue.Severity == q6.ValidationSeverityError {
			blocking = append(blocking, issue)
		}
	}
	return blocking
}

// ECIDMeasurementInitiationFailureIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEContainer []ECIDMeasurementInitiationFailureIEField

// ECIDMeasurementInitiationFailureIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q6.ProtocolIEID
	Criticality   q6.Criticality
	Value         ECIDMeasurementInitiationFailureIEValue

	received q4.CompletePadding
}

func (v ECIDMeasurementInitiationFailureIEField) WithoutReplay() ECIDMeasurementInitiationFailureIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECIDMeasurementInitiationFailureIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationFailureIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q5.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q5.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q5.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q5.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q5.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q5.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECIDMeasurementInitiationFailureIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q5.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationFailureIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q6.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q6.Criticality(criticality)
	var zero ECIDMeasurementInitiationFailureIEValue

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

// UTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEContainer []UTDOAInformationRequestIEField

// UTDOAInformationRequestIEField is the concrete ProtocolIEField[UTDOAInformationRequestIEValue].
type UTDOAInformationRequestIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q6.ProtocolIEID
	Criticality   q6.Criticality
	Value         UTDOAInformationRequestIEValue

	received q4.CompletePadding
}

func (v UTDOAInformationRequestIEField) WithoutReplay() UTDOAInformationRequestIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *UTDOAInformationRequestIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationRequestIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q5.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q5.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q5.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q5.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q5.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q5.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationRequestIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q5.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationRequestIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q6.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q6.Criticality(criticality)
	var zero UTDOAInformationRequestIEValue

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

// CriticalityDiagnosticsValueCodec is the concrete ValueCodec[CriticalityDiagnostics].
type CriticalityDiagnosticsValueCodec struct {
	context q6.BridgeCodecContext
	capture func(CriticalityDiagnostics, q4.DecodeState,

	) (CriticalityDiagnostics, q4.Snapshot,

	)
	compare func(CriticalityDiagnostics, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (CriticalityDiagnostics,

		error)
	encode func(CriticalityDiagnostics,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c CriticalityDiagnosticsValueCodec) New(value CriticalityDiagnostics,

) (CriticalityDiagnosticsAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c CriticalityDiagnosticsValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (CriticalityDiagnosticsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return CriticalityDiagnosticsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CriticalityDiagnosticsValueCodec) EncodeAPER(value CriticalityDiagnosticsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c CriticalityDiagnosticsValueCodec) encodeBudget(value CriticalityDiagnostics,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsValueCodec) encodeChanged(value CriticalityDiagnostics,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ECIDMeasurementInitiationFailureCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCauseIEBinding struct {
	info   q6.FieldInfo
	codec  q9.CauseValueCodec
	inject func(q9.Cause,

	) ECIDMeasurementInitiationFailureIEValue

	get func(*ECIDMeasurementInitiationFailureIEValue,

	) (*q9.Cause,

		bool)
}

func (b ECIDMeasurementInitiationFailureCauseIEBinding) Info() q6.FieldInfo        { return b.info }
func (b ECIDMeasurementInitiationFailureCauseIEBinding) Codec() q9.CauseValueCodec { return b.codec }
func (b ECIDMeasurementInitiationFailureCauseIEBinding) New(value q9.Cause,

) (ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q5.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q5.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationFailureCauseIEBinding) Get(field *ECIDMeasurementInitiationFailureIEField) (*q9.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding struct {
	info   q6.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) ECIDMeasurementInitiationFailureIEValue

	get func(*ECIDMeasurementInitiationFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Info() q6.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q5.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(q5.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Get(field *ECIDMeasurementInitiationFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding is the concrete IEBinding[RequestedSRSTransmissionCharacteristics, UTDOAInformationRequestIEValue].
type UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding struct {
	info   q6.FieldInfo
	codec  q10.RequestedSRSTransmissionCharacteristicsValueCodec
	inject func(q10.RequestedSRSTransmissionCharacteristics,

	) UTDOAInformationRequestIEValue

	get func(*UTDOAInformationRequestIEValue,

	) (*q10.RequestedSRSTransmissionCharacteristics,

		bool)
}

func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Info() q6.FieldInfo {
	return b.info
}
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Codec() q10.RequestedSRSTransmissionCharacteristicsValueCodec {
	return b.codec
}
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) New(value q10.RequestedSRSTransmissionCharacteristics,

) (UTDOAInformationRequestIEField, error) {
	if b.inject == nil {
		return UTDOAInformationRequestIEField{}, q4.OperationError(q5.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationRequestIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationRequestIEField{}, q4.OperationError(q5.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationRequestIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Get(field *UTDOAInformationRequestIEField) (*q10.RequestedSRSTransmissionCharacteristics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MBSFNsubframeConfigurationConcreteValueCodec is the concrete ValueCodec[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationConcreteValueCodec struct {
	context q6.BridgeCodecContext
	capture func(MBSFNsubframeConfiguration, q4.DecodeState,

	) (MBSFNsubframeConfiguration, q4.Snapshot,

	)
	compare func(MBSFNsubframeConfiguration, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MBSFNsubframeConfiguration,

		error)
	encode func(MBSFNsubframeConfiguration,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MBSFNsubframeConfigurationConcreteValueCodec) New(value MBSFNsubframeConfiguration,

) (MBSFNsubframeConfigurationAPERValue, error) {
	if c.encode == nil {
		return MBSFNsubframeConfigurationAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MBSFNsubframeConfigurationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MBSFNsubframeConfigurationConcreteValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MBSFNsubframeConfigurationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MBSFNsubframeConfigurationAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MBSFNsubframeConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MBSFNsubframeConfigurationAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MBSFNsubframeConfigurationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MBSFNsubframeConfigurationConcreteValueCodec) EncodeAPER(value MBSFNsubframeConfigurationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c MBSFNsubframeConfigurationConcreteValueCodec) encodeBudget(value MBSFNsubframeConfiguration,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MBSFNsubframeConfigurationConcreteValueCodec) encodeChanged(value MBSFNsubframeConfiguration,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// MBSFNsubframeConfigurationValueValueCodec is the concrete ValueCodec[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueValueCodec struct {
	context q6.BridgeCodecContext
	capture func(MBSFNsubframeConfigurationValue, q4.DecodeState,

	) (MBSFNsubframeConfigurationValue, q4.Snapshot,

	)
	compare func(MBSFNsubframeConfigurationValue, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MBSFNsubframeConfigurationValue,

		error)
	encode func(MBSFNsubframeConfigurationValue,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MBSFNsubframeConfigurationValueValueCodec) New(value MBSFNsubframeConfigurationValue,

) (MBSFNsubframeConfigurationValueAPERValue, error) {
	if c.encode == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MBSFNsubframeConfigurationValueAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MBSFNsubframeConfigurationValueValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MBSFNsubframeConfigurationValueAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MBSFNsubframeConfigurationValueAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MBSFNsubframeConfigurationValueAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MBSFNsubframeConfigurationValueValueCodec) EncodeAPER(value MBSFNsubframeConfigurationValueAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c MBSFNsubframeConfigurationValueValueCodec) encodeBudget(value MBSFNsubframeConfigurationValue,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MBSFNsubframeConfigurationValueValueCodec) encodeChanged(value MBSFNsubframeConfigurationValue,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// SRSConfigurationForAllCellsValueCodec is the concrete ValueCodec[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsValueCodec struct {
	context q6.BridgeCodecContext
	capture func(SRSConfigurationForAllCells, q4.DecodeState,

	) (SRSConfigurationForAllCells, q4.Snapshot,

	)
	compare func(SRSConfigurationForAllCells, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (SRSConfigurationForAllCells,

		error)
	encode func(SRSConfigurationForAllCells,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c SRSConfigurationForAllCellsValueCodec) New(value SRSConfigurationForAllCells,

) (SRSConfigurationForAllCellsAPERValue, error) {
	if c.encode == nil {
		return SRSConfigurationForAllCellsAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return SRSConfigurationForAllCellsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c SRSConfigurationForAllCellsValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (SRSConfigurationForAllCellsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SRSConfigurationForAllCellsAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return SRSConfigurationForAllCellsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SRSConfigurationForAllCellsAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return SRSConfigurationForAllCellsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SRSConfigurationForAllCellsValueCodec) EncodeAPER(value SRSConfigurationForAllCellsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c SRSConfigurationForAllCellsValueCodec) encodeBudget(value SRSConfigurationForAllCells,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SRSConfigurationForAllCellsValueCodec) encodeChanged(value SRSConfigurationForAllCells,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// SRSConfigurationForOneCellValueCodec is the concrete ValueCodec[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellValueCodec struct {
	context q6.BridgeCodecContext
	capture func(SRSConfigurationForOneCell, q4.DecodeState,

	) (SRSConfigurationForOneCell, q4.Snapshot,

	)
	compare func(SRSConfigurationForOneCell, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (SRSConfigurationForOneCell,

		error)
	encode func(SRSConfigurationForOneCell,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c SRSConfigurationForOneCellValueCodec) New(value SRSConfigurationForOneCell,

) (SRSConfigurationForOneCellAPERValue, error) {
	if c.encode == nil {
		return SRSConfigurationForOneCellAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return SRSConfigurationForOneCellAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRSConfigurationForOneCellAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return SRSConfigurationForOneCellAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c SRSConfigurationForOneCellValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (SRSConfigurationForOneCellAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SRSConfigurationForOneCellAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return SRSConfigurationForOneCellAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SRSConfigurationForOneCellAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return SRSConfigurationForOneCellAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return SRSConfigurationForOneCellAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SRSConfigurationForOneCellValueCodec) EncodeAPER(value SRSConfigurationForOneCellAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c SRSConfigurationForOneCellValueCodec) encodeBudget(value SRSConfigurationForOneCell,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SRSConfigurationForOneCellValueCodec) encodeChanged(value SRSConfigurationForOneCell,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// SubframeallocationValueCodec is the concrete ValueCodec[Subframeallocation].
type SubframeallocationValueCodec struct {
	context q6.BridgeCodecContext
	capture func(Subframeallocation, q4.DecodeState,

	) (Subframeallocation, q4.Snapshot,

	)
	compare func(Subframeallocation, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (Subframeallocation,

		error)
	encode func(Subframeallocation,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c SubframeallocationValueCodec) New(value Subframeallocation,

) (SubframeallocationAPERValue, error) {
	if c.encode == nil {
		return SubframeallocationAPERValue{}, q4.OperationError(q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return SubframeallocationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubframeallocationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return SubframeallocationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c SubframeallocationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (SubframeallocationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SubframeallocationAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return SubframeallocationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SubframeallocationAPERValue{}, q4.DecodeReport{}, q5.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return SubframeallocationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return SubframeallocationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SubframeallocationValueCodec) EncodeAPER(value SubframeallocationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q5.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
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
func (c SubframeallocationValueCodec) encodeBudget(value Subframeallocation,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SubframeallocationValueCodec) encodeChanged(value Subframeallocation,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}
func BridgeAddOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields q8.AddOTDOACellsExtIEsExtContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget) ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.AddOTDOACellsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(q8.AddOTDOACellsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAddOTDOACellsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationExtIEsValueValidateLPPaExtensionContainer(fields q8.AssistanceInformationExtIEsExtContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget) ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.AssistanceInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(q8.AssistanceInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaExtensionContainer(fields q8.AssistanceInformationFailureListExtIEsExtContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget) ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.AssistanceInformationFailureListExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(q8.AssistanceInformationFailureListExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaExtensionContainer(fields q8.AssistanceInformationMetaDataExtIEsExtContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget) ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.AssistanceInformationMetaDataExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(q8.AssistanceInformationMetaDataExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// CriticalityDiagnosticsAPERValue is the concrete APERValue[CriticalityDiagnostics].
type CriticalityDiagnosticsAPERValue struct {
	context q6.BridgeCodecContext
	Value   CriticalityDiagnostics

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v CriticalityDiagnosticsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v CriticalityDiagnosticsAPERValue) WithoutReplay() CriticalityDiagnosticsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNsubframeConfigurationAPERValue is the concrete APERValue[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationAPERValue struct {
	context q6.BridgeCodecContext
	Value   MBSFNsubframeConfiguration

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MBSFNsubframeConfigurationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MBSFNsubframeConfigurationAPERValue) WithoutReplay() MBSFNsubframeConfigurationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNsubframeConfigurationValueAPERValue is the concrete APERValue[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueAPERValue struct {
	context q6.BridgeCodecContext
	Value   MBSFNsubframeConfigurationValue

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MBSFNsubframeConfigurationValueAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MBSFNsubframeConfigurationValueAPERValue) WithoutReplay() MBSFNsubframeConfigurationValueAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// SRSConfigurationForAllCellsAPERValue is the concrete APERValue[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsAPERValue struct {
	context q6.BridgeCodecContext
	Value   SRSConfigurationForAllCells

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v SRSConfigurationForAllCellsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v SRSConfigurationForAllCellsAPERValue) WithoutReplay() SRSConfigurationForAllCellsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// SRSConfigurationForOneCellAPERValue is the concrete APERValue[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellAPERValue struct {
	context q6.BridgeCodecContext
	Value   SRSConfigurationForOneCell

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v SRSConfigurationForOneCellAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v SRSConfigurationForOneCellAPERValue) WithoutReplay() SRSConfigurationForOneCellAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubframeallocationAPERValue is the concrete APERValue[Subframeallocation].
type SubframeallocationAPERValue struct {
	context q6.BridgeCodecContext
	Value   Subframeallocation

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v SubframeallocationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v SubframeallocationAPERValue) WithoutReplay() SubframeallocationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAddOTDOACellsExtIEsValueValidateLPPaIEContainer(fields q8.AddOTDOACellsExtIEsIEContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if report.err != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			report.err = err
			return report
		}
		location := q4.Location{Path: q4.Path(q5.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeAddOTDOACellsExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			report.addDeferred(q6.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if report.err != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAssistanceInformationExtIEsValueValidateLPPaIEContainer(fields q8.AssistanceInformationExtIEsIEContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if report.err != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			report.err = err
			return report
		}
		location := q4.Location{Path: q4.Path(q5.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeAssistanceInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeAssistanceInformationExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			report.addDeferred(q6.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if report.err != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaIEContainer(fields q8.AssistanceInformationFailureListExtIEsIEContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if report.err != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			report.err = err
			return report
		}
		location := q4.Location{Path: q4.Path(q5.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			report.addDeferred(q6.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if report.err != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaIEContainer(fields q8.AssistanceInformationMetaDataExtIEsIEContainer, rows []q6.FieldInfo, path string, budget *q4.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[q6.ProtocolIEID]int, len(rows))
	counts := make(map[q6.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if report.err != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			report.err = err
			return report
		}
		location := q4.Location{Path: q4.Path(q5.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: q6.ValueIDMismatch, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.id", location.Path))}, Table: func() q6.TableID {
				sealed := q6.TableID{}
				*q6.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q6.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: q6.RepeatedIE, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q6.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q6.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: q6.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q6.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: q6.WrongCriticality, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q5.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q6.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: q6.WrongOrder, Severity: q6.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q6.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: q6.MissingMandatory, Severity: q6.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q6.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q6.MissingMandatory), row.Rule}})
		}
		if row.Presence == q6.PresenceConditional {
			report.addDeferred(q6.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if report.err != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// CriticalityDiagnostics represents the ASN.1 type CriticalityDiagnostics (SEQUENCE).
type CriticalityDiagnostics struct {
	replay                         q4.Snapshot
	stream                         q4.WireSpan
	withoutReplay                  bool
	received                       bool
	receivedBytes                  q4.WireSpan
	ProcedureCode                  *q6.ProcedureCode                           `asn1:"tag:0,context,implicit,optional" json:"ProcedureCode,omitempty"`
	TriggeringMessage              *q6.TriggeringMessage                       `asn1:"tag:1,context,implicit,optional" json:"TriggeringMessage,omitempty"`
	ProcedureCriticality           *q6.Criticality                             `asn1:"tag:2,context,implicit,optional" json:"ProcedureCriticality,omitempty"`
	LppatransactionID              *q6.LPPATransactionID                       `asn1:"tag:3,context,implicit,optional" json:"LppatransactionID,omitempty"`
	IEsCriticalityDiagnostics      q9.CriticalityDiagnosticsIEList             `asn1:"tag:4,context,implicit,optional" json:"IEsCriticalityDiagnostics,omitzero"`
	iEsCriticalityDiagnosticsIndef bool                                        `asn1:"-" json:"-"`
	IEExtensions                   q8.CriticalityDiagnosticsExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                        `asn1:"-" json:"-"`
	extCount                       int64                                       `asn1:"-" json:"-"`
	extPresent                     []bool                                      `asn1:"-" json:"-"`
	extData                        [][]byte                                    `asn1:"-" json:"-"`
	perPadding                     q4.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding                  []q4.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin                      []q4.OpaqueOrigin
	extWire                        []q4.WireSpan
}
type MBSFNsubframeConfiguration = []MBSFNsubframeConfigurationValue

// MBSFNsubframeConfigurationValue represents the ASN.1 type MBSFNsubframeConfigurationValue (SEQUENCE).
type MBSFNsubframeConfigurationValue struct {
	replay                     q4.Snapshot
	stream                     q4.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              q4.WireSpan
	RadioframeAllocationPeriod int64              `asn1:"tag:0,context,implicit"`
	RadioframeAllocationOffset int64              `asn1:"tag:1,context,implicit"`
	SubframeAllocation         Subframeallocation `asn1:"tag:2,context,explicit"`
	perPadding                 q4.CompletePadding `asn1:"-" json:"-"`
}
type SRSConfigurationForAllCells = []SRSConfigurationForOneCell

// SRSConfigurationForOneCell represents the ASN.1 type SRSConfigurationForOneCell (SEQUENCE).
type SRSConfigurationForOneCell struct {
	replay                 q4.Snapshot
	stream                 q4.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          q4.WireSpan
	Pci                    q6.PCI                   `asn1:"tag:0,context,implicit"`
	UlEarfcn               q6.EARFCN                `asn1:"tag:1,context,implicit"`
	UlBandwidth            int64                    `asn1:"tag:2,context,implicit"`
	UlCyclicPrefixLength   q6.CPLength              `asn1:"tag:3,context,implicit"`
	SrsBandwidthConfig     int64                    `asn1:"tag:4,context,implicit"`
	SrsBandwidth           int64                    `asn1:"tag:5,context,implicit"`
	SrsAntennaPort         int64                    `asn1:"tag:6,context,implicit"`
	SrsHoppingBandwidth    int64                    `asn1:"tag:7,context,implicit"`
	SrsCyclicShift         int64                    `asn1:"tag:8,context,implicit"`
	SrsConfigIndex         int64                    `asn1:"tag:9,context,implicit"`
	MaxUpPts               *int64                   `asn1:"tag:10,context,implicit,optional" json:"MaxUpPts,omitempty"`
	TransmissionComb       int64                    `asn1:"tag:11,context,implicit"`
	FreqDomainPosition     int64                    `asn1:"tag:12,context,implicit"`
	GroupHoppingEnabled    bool                     `asn1:"tag:13,context,implicit"`
	groupHoppingEnabledRaw byte                     `asn1:"-" json:"-"`
	DeltaSS                *int64                   `asn1:"tag:14,context,implicit,optional" json:"DeltaSS,omitempty"`
	SfnInitialisationTime  q6.SFNInitialisationTime `asn1:"tag:15,context,implicit"`
	extCount               int64                    `asn1:"-" json:"-"`
	extPresent             []bool                   `asn1:"-" json:"-"`
	extData                [][]byte                 `asn1:"-" json:"-"`
	perPadding             q4.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding          []q4.CompletePadding     `asn1:"-" json:"-"`
	extOrigin              []q4.OpaqueOrigin
	extWire                []q4.WireSpan
}

// Subframeallocation represents the ASN.1 CHOICE type Subframeallocation.
type Subframeallocation struct {
	replay             q4.Snapshot
	stream             q4.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q4.WireSpan
	Choice             int
	perPadding         q4.CompletePadding `json:"-"`
	perOpenTypePadding q4.CompletePadding `json:"-"`
	OneFrame           *q7.BitString      `json:"OneFrame,omitempty"`
	FourFrames         *q7.BitString      `json:"FourFrames,omitempty"`
}
type BridgeAsn1cAPERAssistanceInformationFailureListListValue struct {
	Value q9.AssistanceInformationFailureList
}

func (v *CriticalityDiagnostics) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnostics) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, v.ProcedureCode != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.TriggeringMessage != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.ProcedureCriticality != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.LppatransactionID != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEsCriticalityDiagnostics != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ProcedureCode != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.ProcedureCode), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false); err != nil {
			return q5.Errorf("encoding procedureCode: %w", err)
		}
	}
	if v.TriggeringMessage != nil {
		if err := q4.EncodeEnumeratedAligned(bb, int64(*v.TriggeringMessage), 3, false); err != nil {
			return q5.Errorf("encoding triggeringMessage: %w", err)
		}
	}
	if v.ProcedureCriticality != nil {
		if err := q4.EncodeEnumeratedAligned(bb, int64(*v.ProcedureCriticality), 3, false); err != nil {
			return q5.Errorf("encoding procedureCriticality: %w", err)
		}
	}
	if v.LppatransactionID != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.LppatransactionID), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false); err != nil {
			return q5.Errorf("encoding lppatransactionID: %w", err)
		}
	}
	if v.IEsCriticalityDiagnostics != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEsCriticalityDiagnostics)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentOffset_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics)) || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics:])) {
				return q5.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics : fragmentOffset_iescriticalitydiagnostics+fragmentLength_iescriticalitydiagnostics] {
				if err := q9.BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q5.Errorf("encoding iEsCriticalityDiagnostics element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q5.Errorf("encoding iEsCriticalityDiagnostics: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q5.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q8.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q5.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q5.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q5.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q5.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q5.Errorf("extension count out of range")
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

// UnmarshalAPER decodes CriticalityDiagnostics from APER format.
func (v *CriticalityDiagnostics) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnostics with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnostics) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	padding, err := q4.CaptureFinalBits(bb, "CriticalityDiagnostics")
	if err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnostics")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *CriticalityDiagnostics) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnostics{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_procedurecode, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_triggeringmessage, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_procedurecriticality, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_lppatransactionid, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_iescriticalitydiagnostics, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_procedurecode {
		val_procedurecode, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false)
		if err != nil {
			return q7.WrapDecodePath(err, "ProcedureCode")
		}
		tmp_procedurecode := q6.ProcedureCode(val_procedurecode)
		if err := q4.ChargeValue(bb, tmp_procedurecode); err != nil {
			return err
		}
		v.ProcedureCode = (*q6.ProcedureCode)(bb.OwnInt64(int64(tmp_procedurecode)))
	}
	if opt_triggeringmessage {
		val_triggeringmessage, err := q4.DecodeEnumeratedAligned(bb, 3, false, q4.EnumerationSource{KnownExtensions: 0, Path: "TriggeringMessage"})
		if err != nil {
			return q7.WrapDecodePath(err, "TriggeringMessage")
		}
		tmp_triggeringmessage := q6.TriggeringMessage(val_triggeringmessage)
		if err := q4.ChargeValue(bb, tmp_triggeringmessage); err != nil {
			return err
		}
		v.TriggeringMessage = (*q6.TriggeringMessage)(bb.OwnInt64(int64(tmp_triggeringmessage)))
	}
	if opt_procedurecriticality {
		val_procedurecriticality, err := q4.DecodeEnumeratedAligned(bb, 3, false, q4.EnumerationSource{KnownExtensions: 0, Path: "ProcedureCriticality"})
		if err != nil {
			return q7.WrapDecodePath(err, "ProcedureCriticality")
		}
		tmp_procedurecriticality := q6.Criticality(val_procedurecriticality)
		if err := q4.ChargeValue(bb, tmp_procedurecriticality); err != nil {
			return err
		}
		v.ProcedureCriticality = (*q6.Criticality)(bb.OwnInt64(int64(tmp_procedurecriticality)))
	}
	if opt_lppatransactionid {
		val_lppatransactionid, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false)
		if err != nil {
			return q7.WrapDecodePath(err, "LppatransactionID")
		}
		tmp_lppatransactionid := q6.LPPATransactionID(val_lppatransactionid)
		if err := q4.ChargeValue(bb, tmp_lppatransactionid); err != nil {
			return err
		}
		v.LppatransactionID = (*q6.LPPATransactionID)(bb.OwnInt64(int64(tmp_lppatransactionid)))
	}
	if opt_iescriticalitydiagnostics {
		toleranceMark_iescriticalitydiagnostics := bb.EnterComponent("IEsCriticalityDiagnostics")
		tmp_iescriticalitydiagnostics := make(q9.CriticalityDiagnosticsIEList, 0)
		_, errCollection_iescriticalitydiagnostics := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(^uint(0)>>1) || fragmentOffset_iescriticalitydiagnostics > int64(^uint(0)>>1)-fragmentLength_iescriticalitydiagnostics {
				return q5.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_iescriticalitydiagnostics; i++ {
				var elem q9.CriticalityDiagnosticsIEListElem
				elementMark := bb.EnterIndex(fragmentOffset_iescriticalitydiagnostics + i)
				if err := q9.BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q5.Sprintf("IEsCriticalityDiagnostics[%d]", fragmentOffset_iescriticalitydiagnostics+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_iescriticalitydiagnostics, elem); err != nil {
					return err
				} else {
					tmp_iescriticalitydiagnostics = next
				}
			}
			return nil
		})
		if errCollection_iescriticalitydiagnostics != nil {
			return q7.WrapDecodePath(errCollection_iescriticalitydiagnostics, "IEsCriticalityDiagnostics")
		}
		v.IEsCriticalityDiagnostics = tmp_iescriticalitydiagnostics
		bb.LeaveComponent(toleranceMark_iescriticalitydiagnostics)
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q8.CriticalityDiagnosticsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q5.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q8.CriticalityDiagnosticsExtIEsExtField
				if err := q8.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q5.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q5.Errorf("extension count out of range")
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
			return q5.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q5.Sprintf("ExtData_[%d]", i))
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

type BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue struct {
	Value q9.CriticalityDiagnosticsIEList
}
type BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue struct {
	Value q13.InterRATMeasurementQuantities
}
type BridgeAsn1cAPERMeasurementQuantitiesListValue struct{ Value q13.MeasurementQuantities }
type BridgeAsn1cAPERMBSFNsubframeConfigurationListValue struct{ Value MBSFNsubframeConfiguration }

// MarshalAPER encodes MBSFNsubframeConfigurationValue to APER format.
func (v *MBSFNsubframeConfigurationValue) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if err := q4.EncodeEnumeratedAligned(bb, int64(v.RadioframeAllocationPeriod), 6, false); err != nil {
		return q5.Errorf("encoding radioframeAllocationPeriod: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.RadioframeAllocationOffset), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7), false); err != nil {
		return q5.Errorf("encoding radioframeAllocationOffset: %w", err)
	}
	if err := v.SubframeAllocation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return q5.Errorf("encoding subframeAllocation: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes MBSFNsubframeConfigurationValue from APER format.
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNsubframeConfigurationValue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	padding, err := q4.CaptureFinalBits(bb, "MBSFNsubframeConfigurationValue")
	if err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNsubframeConfigurationValue{}
	val_radioframeallocationperiod, err := q4.DecodeEnumeratedAligned(bb, 6, false, q4.EnumerationSource{KnownExtensions: 0, Path: "RadioframeAllocationPeriod"})
	if err != nil {
		return q7.WrapDecodePath(err, "RadioframeAllocationPeriod")
	}
	v.RadioframeAllocationPeriod = val_radioframeallocationperiod
	val_radioframeallocationoffset, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7), false)
	if err != nil {
		return q7.WrapDecodePath(err, "RadioframeAllocationOffset")
	}
	v.RadioframeAllocationOffset = val_radioframeallocationoffset
	if err := v.SubframeAllocation.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "SubframeAllocation")
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

type BridgeAsn1cAPERPosSIBSegmentsListValue struct{ Value q10.PosSIBSegments }
type BridgeAsn1cAPERSRSConfigurationForAllCellsListValue struct{ Value SRSConfigurationForAllCells }

// MarshalAPER encodes SRSConfigurationForOneCell to APER format.
func (v *SRSConfigurationForOneCell) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SRSConfigurationForOneCell) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, v.MaxUpPts != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.DeltaSS != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.Pci, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound17, true); err != nil {
		return q5.Errorf("encoding pci: %w", err)
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound20, true); err != nil {
		return q5.Errorf("encoding ul-earfcn: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.UlBandwidth), 6, false); err != nil {
		return q5.Errorf("encoding ul-bandwidth: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.UlCyclicPrefixLength), 2, true); err != nil {
		return q5.Errorf("encoding ul-cyclicPrefixLength: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidthConfig), 8, false); err != nil {
		return q5.Errorf("encoding srs-BandwidthConfig: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidth), 4, false); err != nil {
		return q5.Errorf("encoding srs-Bandwidth: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.SrsAntennaPort), 3, true); err != nil {
		return q5.Errorf("encoding srs-AntennaPort: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.SrsHoppingBandwidth), 4, false); err != nil {
		return q5.Errorf("encoding srs-HoppingBandwidth: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.SrsCyclicShift), 8, false); err != nil {
		return q5.Errorf("encoding srs-cyclicShift: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.SrsConfigIndex), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1023), false); err != nil {
		return q5.Errorf("encoding srs-ConfigIndex: %w", err)
	}
	if v.MaxUpPts != nil {
		if err := q4.EncodeEnumeratedAligned(bb, int64(*v.MaxUpPts), 1, false); err != nil {
			return q5.Errorf("encoding maxUpPts: %w", err)
		}
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.TransmissionComb), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1), false); err != nil {
		return q5.Errorf("encoding transmissionComb: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.FreqDomainPosition), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(23), false); err != nil {
		return q5.Errorf("encoding freqDomainPosition: %w", err)
	}
	if err := q4.EncodeBoolean(bb, v.GroupHoppingEnabled); err != nil {
		return q5.Errorf("encoding groupHoppingEnabled: %w", err)
	}
	if v.DeltaSS != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.DeltaSS), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(29), false); err != nil {
			return q5.Errorf("encoding deltaSS: %w", err)
		}
	}
	if err := q4.EncodeBitStringAligned(bb, v.SfnInitialisationTime.Bytes, v.SfnInitialisationTime.BitLength, 64, 64, true); err != nil {
		return q5.Errorf("encoding sfnInitialisationTime: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q5.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q5.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q5.Errorf("extension count out of range")
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

// UnmarshalAPER decodes SRSConfigurationForOneCell from APER format.
func (v *SRSConfigurationForOneCell) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SRSConfigurationForOneCell with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SRSConfigurationForOneCell) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	padding, err := q4.CaptureFinalBits(bb, "SRSConfigurationForOneCell")
	if err != nil {
		return q7.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SRSConfigurationForOneCell) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SRSConfigurationForOneCell{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_maxuppts, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_deltass, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := q4.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return q7.WrapDecodePath(err, "Pci")
	}
	v.Pci = val_pci
	val_ulearfcn, err := q4.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound1, q6.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return q7.WrapDecodePath(err, "UlEarfcn")
	}
	v.UlEarfcn = val_ulearfcn
	val_ulbandwidth, err := q4.DecodeEnumeratedAligned(bb, 6, false, q4.EnumerationSource{KnownExtensions: 0, Path: "UlBandwidth"})
	if err != nil {
		return q7.WrapDecodePath(err, "UlBandwidth")
	}
	v.UlBandwidth = val_ulbandwidth
	val_ulcyclicprefixlength, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "UlCyclicPrefixLength"})
	if err != nil {
		return q7.WrapDecodePath(err, "UlCyclicPrefixLength")
	}
	v.UlCyclicPrefixLength = q6.CPLength(val_ulcyclicprefixlength)
	val_srsbandwidthconfig, err := q4.DecodeEnumeratedAligned(bb, 8, false, q4.EnumerationSource{KnownExtensions: 0, Path: "SrsBandwidthConfig"})
	if err != nil {
		return q7.WrapDecodePath(err, "SrsBandwidthConfig")
	}
	v.SrsBandwidthConfig = val_srsbandwidthconfig
	val_srsbandwidth, err := q4.DecodeEnumeratedAligned(bb, 4, false, q4.EnumerationSource{KnownExtensions: 0, Path: "SrsBandwidth"})
	if err != nil {
		return q7.WrapDecodePath(err, "SrsBandwidth")
	}
	v.SrsBandwidth = val_srsbandwidth
	val_srsantennaport, err := q4.DecodeEnumeratedAligned(bb, 3, true, q4.EnumerationSource{KnownExtensions: 0, Path: "SrsAntennaPort"})
	if err != nil {
		return q7.WrapDecodePath(err, "SrsAntennaPort")
	}
	v.SrsAntennaPort = val_srsantennaport
	val_srshoppingbandwidth, err := q4.DecodeEnumeratedAligned(bb, 4, false, q4.EnumerationSource{KnownExtensions: 0, Path: "SrsHoppingBandwidth"})
	if err != nil {
		return q7.WrapDecodePath(err, "SrsHoppingBandwidth")
	}
	v.SrsHoppingBandwidth = val_srshoppingbandwidth
	val_srscyclicshift, err := q4.DecodeEnumeratedAligned(bb, 8, false, q4.EnumerationSource{KnownExtensions: 0, Path: "SrsCyclicShift"})
	if err != nil {
		return q7.WrapDecodePath(err, "SrsCyclicShift")
	}
	v.SrsCyclicShift = val_srscyclicshift
	val_srsconfigindex, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1023), false)
	if err != nil {
		return q7.WrapDecodePath(err, "SrsConfigIndex")
	}
	v.SrsConfigIndex = val_srsconfigindex
	if opt_maxuppts {
		val_maxuppts, err := q4.DecodeEnumeratedAligned(bb, 1, false, q4.EnumerationSource{KnownExtensions: 0, Path: "MaxUpPts"})
		if err != nil {
			return q7.WrapDecodePath(err, "MaxUpPts")
		}
		if err := q4.ChargeValue(bb, val_maxuppts); err != nil {
			return err
		}
		v.MaxUpPts = (*int64)(bb.OwnInt64(int64(val_maxuppts)))
	}
	val_transmissioncomb, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1), false)
	if err != nil {
		return q7.WrapDecodePath(err, "TransmissionComb")
	}
	v.TransmissionComb = val_transmissioncomb
	val_freqdomainposition, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(23), false)
	if err != nil {
		return q7.WrapDecodePath(err, "FreqDomainPosition")
	}
	v.FreqDomainPosition = val_freqdomainposition
	val_grouphoppingenabled, err := q4.DecodeBoolean(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "GroupHoppingEnabled")
	}
	v.GroupHoppingEnabled = val_grouphoppingenabled
	if opt_deltass {
		val_deltass, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(29), false)
		if err != nil {
			return q7.WrapDecodePath(err, "DeltaSS")
		}
		if err := q4.ChargeValue(bb, val_deltass); err != nil {
			return err
		}
		v.DeltaSS = (*int64)(bb.OwnInt64(int64(val_deltass)))
	}
	bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := q4.DecodeBitStringAligned(bb, 64, 64, true)
	if err != nil {
		return q7.WrapDecodePath(err, "SfnInitialisationTime")
	}
	v.SfnInitialisationTime = q7.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q5.Errorf("extension count out of range")
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
			return q5.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q5.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes Subframeallocation to APER format.
func (v *Subframeallocation) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Subframeallocation) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.replay.ReplayTo(v.stream, bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Choice < 1 {
		return q5.Errorf("%s choice %d must be positive", "Subframeallocation:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q5.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case q6.SubframeallocationChoiceOneFrame:
		if v.OneFrame == nil {
			return q5.Errorf("choice alternative oneFrame is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.OneFrame.Bytes, v.OneFrame.BitLength, 6, 6, true); err != nil {
			return q5.Errorf("encoding oneFrame: %w", err)
		}
	case q6.SubframeallocationChoiceFourFrames:
		if v.FourFrames == nil {
			return q5.Errorf("choice alternative fourFrames is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.FourFrames.Bytes, v.FourFrames.BitLength, 24, 24, true); err != nil {
			return q5.Errorf("encoding fourFrames: %w", err)
		}
	default:
		return q5.Errorf("unknown Subframeallocation choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Subframeallocation from APER format.
func (v *Subframeallocation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Subframeallocation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Subframeallocation) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "Subframeallocation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "Subframeallocation")
	}
	padding, err := q4.CaptureFinalBits(bb, "Subframeallocation")
	if err != nil {
		return q7.WrapDecodePath(err, "Subframeallocation")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Subframeallocation) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Subframeallocation{}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q5.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q6.SubframeallocationChoiceOneFrame:
		bsBytes_oneframe, bsBitLen_oneframe, err := q4.DecodeBitStringAligned(bb, 6, 6, true)
		if err != nil {
			return q7.WrapDecodePath(err, "OneFrame")
		}
		tmp_oneframe := q7.BitString{Bytes: bsBytes_oneframe, BitLength: bsBitLen_oneframe}
		if err := q4.ChargeValue(bb, tmp_oneframe); err != nil {
			return err
		}
		v.OneFrame = &tmp_oneframe
	case q6.SubframeallocationChoiceFourFrames:
		bsBytes_fourframes, bsBitLen_fourframes, err := q4.DecodeBitStringAligned(bb, 24, 24, true)
		if err != nil {
			return q7.WrapDecodePath(err, "FourFrames")
		}
		tmp_fourframes := q7.BitString{Bytes: bsBytes_fourframes, BitLength: bsBitLen_fourframes}
		if err := q4.ChargeValue(bb, tmp_fourframes); err != nil {
			return err
		}
		v.FourFrames = &tmp_fourframes
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnostics) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnostics", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnostics) WithoutReplay() CriticalityDiagnostics {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero CriticalityDiagnostics
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNsubframeConfigurationValue) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNsubframeConfigurationValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNsubframeConfigurationValue) WithoutReplay() MBSFNsubframeConfigurationValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MBSFNsubframeConfigurationValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SRSConfigurationForOneCell) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "SRSConfigurationForOneCell", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SRSConfigurationForOneCell) WithoutReplay() SRSConfigurationForOneCell {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero SRSConfigurationForOneCell
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Subframeallocation) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "Subframeallocation", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Subframeallocation) WithoutReplay() Subframeallocation {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero Subframeallocation
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnostics) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnostics) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q5.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q5.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnostics) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q5.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q5.Sprintf("CriticalityDiagnostics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SRSConfigurationForOneCell) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SRSConfigurationForOneCell) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q5.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q5.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SRSConfigurationForOneCell) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q5.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q5.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *CriticalityDiagnostics) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "CriticalityDiagnostics")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "CriticalityDiagnostics")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnostics(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "CriticalityDiagnostics")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "CriticalityDiagnostics")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "CriticalityDiagnostics")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "CriticalityDiagnostics")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "CriticalityDiagnostics")
}
func (v *CriticalityDiagnostics) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnostics) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnostics) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaCriticalityDiagnostics(v, &s)
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
func (v *CriticalityDiagnostics) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnostics) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *MBSFNsubframeConfigurationValue) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MBSFNsubframeConfigurationValue")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationValue(v, &s)
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
func (v *MBSFNsubframeConfigurationValue) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}
func (v *SRSConfigurationForOneCell) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "SRSConfigurationForOneCell")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "SRSConfigurationForOneCell")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaSRSConfigurationForOneCell(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "SRSConfigurationForOneCell")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "SRSConfigurationForOneCell")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "SRSConfigurationForOneCell")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "SRSConfigurationForOneCell")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "SRSConfigurationForOneCell")
}
func (v *SRSConfigurationForOneCell) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SRSConfigurationForOneCell) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SRSConfigurationForOneCell) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaSRSConfigurationForOneCell(v, &s)
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
func (v *SRSConfigurationForOneCell) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SRSConfigurationForOneCell) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *Subframeallocation) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "Subframeallocation")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "Subframeallocation")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaSubframeallocation(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "Subframeallocation")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "Subframeallocation")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "Subframeallocation")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "Subframeallocation")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "Subframeallocation")
}
func (v *Subframeallocation) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *Subframeallocation) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *Subframeallocation) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaSubframeallocation(v, &s)
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
func (v *Subframeallocation) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *Subframeallocation) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *CriticalityDiagnostics) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "CriticalityDiagnostics")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnostics
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnostics(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnostics{}
		return report, q4.OperationError(err, "CriticalityDiagnostics")
	}
	*v = decoded
	return report, q4.OperationError(nil, "CriticalityDiagnostics")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MBSFNsubframeConfigurationValue) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MBSFNsubframeConfigurationValue")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MBSFNsubframeConfigurationValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMBSFNsubframeConfigurationValue(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MBSFNsubframeConfigurationValue{}
		return report, q4.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MBSFNsubframeConfigurationValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SRSConfigurationForOneCell) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "SRSConfigurationForOneCell")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded SRSConfigurationForOneCell
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSRSConfigurationForOneCell(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = SRSConfigurationForOneCell{}
		return report, q4.OperationError(err, "SRSConfigurationForOneCell")
	}
	*v = decoded
	return report, q4.OperationError(nil, "SRSConfigurationForOneCell")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *Subframeallocation) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "Subframeallocation")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded Subframeallocation
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSubframeallocation(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = Subframeallocation{}
		return report, q4.OperationError(err, "Subframeallocation")
	}
	*v = decoded
	return report, q4.OperationError(nil, "Subframeallocation")
}

type BridgeAsn1cAPEROTDOAInformationTypeListValue struct{ Value q14.OTDOAInformationType }

func BridgeCaptureLPPaAssistanceInformationFailureList(v *q9.AssistanceInformationFailureList, s *q4.SemanticCapture) {
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
			q9.BridgeCaptureLPPaAssistanceInformationFailureListElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaAssistanceInformationFailureList(v *q9.AssistanceInformationFailureList, s *q4.SemanticComparison) {
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
			q9.BridgeCompareLPPaAssistanceInformationFailureListElem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaCriticalityDiagnostics(v *CriticalityDiagnostics, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	{
		f := s.Begin()
		s.Bool(v.ProcedureCode == nil)
		if v.ProcedureCode != nil {
			q6.BridgeCaptureLPPaProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			q6.BridgeCaptureLPPaTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			q6.BridgeCaptureLPPaCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.LppatransactionID == nil)
		if v.LppatransactionID != nil {
			q6.BridgeCaptureLPPaLPPATransactionID(v.LppatransactionID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	q12.BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnostics(v *CriticalityDiagnostics, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.Bool(v.ProcedureCode == nil)
		if v.ProcedureCode != nil {
			q11.BridgeCompareLPPaProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			q8.BridgeCompareLPPaTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			q11.BridgeCompareLPPaCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.LppatransactionID == nil)
		if v.LppatransactionID != nil {
			q11.BridgeCompareLPPaLPPATransactionID(v.LppatransactionID, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	BridgeCompareLPPaCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	q12.BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEList(v *q9.CriticalityDiagnosticsIEList, s *q4.SemanticCapture) {
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
			q9.BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEList(v *q9.CriticalityDiagnosticsIEList, s *q4.SemanticComparison) {
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
			q9.BridgeCompareLPPaCriticalityDiagnosticsIEListElem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaECIDMeasurementInitiationFailureIEValue(v *ECIDMeasurementInitiationFailureIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q6.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q6.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q6.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q6.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q9.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case q6.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationFailureIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationFailureIEValue) captureSemantics(s q4.SemanticCapture) ECIDMeasurementInitiationFailureIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationFailureIEValue(v *ECIDMeasurementInitiationFailureIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q6.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q11.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q6.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q9.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q6.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationFailureIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationFailureIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementInitiationFailureIEValue) WithoutReplay() ECIDMeasurementInitiationFailureIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaMBSFNsubframeConfiguration(v *MBSFNsubframeConfiguration, s *q4.SemanticCapture) {
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
			BridgeCaptureLPPaMBSFNsubframeConfigurationValue(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaMBSFNsubframeConfigurationValue(v *MBSFNsubframeConfigurationValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.RadioframeAllocationPeriod))
	s.Int(int64(v.RadioframeAllocationOffset))
	BridgeCaptureLPPaSubframeallocation(&v.SubframeAllocation, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMBSFNsubframeConfigurationValue(v *MBSFNsubframeConfigurationValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.RadioframeAllocationPeriod))
	s.Int(int64(v.RadioframeAllocationOffset))
	BridgeCompareLPPaSubframeallocation(&v.SubframeAllocation, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBSegments(v *q10.PosSIBSegments, s *q4.SemanticCapture) {
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
			q10.BridgeCaptureLPPaPosSIBSegmentsElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaSRSConfigurationForAllCells(v *SRSConfigurationForAllCells, s *q4.SemanticCapture) {
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
			BridgeCaptureLPPaSRSConfigurationForOneCell(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaSRSConfigurationForOneCell(v *SRSConfigurationForOneCell, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q6.BridgeCaptureLPPaPCI(&v.Pci, s)
	q6.BridgeCaptureLPPaEARFCN(&v.UlEarfcn, s)
	s.Int(int64(v.UlBandwidth))
	q6.BridgeCaptureLPPaCPLength(&v.UlCyclicPrefixLength, s)
	s.Int(int64(v.SrsBandwidthConfig))
	s.Int(int64(v.SrsBandwidth))
	s.Int(int64(v.SrsAntennaPort))
	s.Int(int64(v.SrsHoppingBandwidth))
	s.Int(int64(v.SrsCyclicShift))
	s.Int(int64(v.SrsConfigIndex))
	{
		f := s.Begin()
		s.Bool(v.MaxUpPts == nil)
		if v.MaxUpPts != nil {
			s.Int(int64((*v.MaxUpPts)))
		}
		s.End(f, nil, false)
	}
	s.Int(int64(v.TransmissionComb))
	s.Int(int64(v.FreqDomainPosition))
	s.Bool(v.GroupHoppingEnabled)
	s.Uint(uint64(v.groupHoppingEnabledRaw))
	{
		f := s.Begin()
		s.Bool(v.DeltaSS == nil)
		if v.DeltaSS != nil {
			s.Int(int64((*v.DeltaSS)))
		}
		s.End(f, nil, false)
	}
	q6.BridgeCaptureLPPaSFNInitialisationTime(&v.SfnInitialisationTime, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForOneCell(v *SRSConfigurationForOneCell, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaPCI(&v.Pci, s)
	q11.BridgeCompareLPPaEARFCN(&v.UlEarfcn, s)
	s.Int(int64(v.UlBandwidth))
	q11.BridgeCompareLPPaCPLength(&v.UlCyclicPrefixLength, s)
	s.Int(int64(v.SrsBandwidthConfig))
	s.Int(int64(v.SrsBandwidth))
	s.Int(int64(v.SrsAntennaPort))
	s.Int(int64(v.SrsHoppingBandwidth))
	s.Int(int64(v.SrsCyclicShift))
	s.Int(int64(v.SrsConfigIndex))
	{
		f := s.Begin()
		s.Bool(v.MaxUpPts == nil)
		if v.MaxUpPts != nil {
			s.Int(int64((*v.MaxUpPts)))
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Int(int64(v.TransmissionComb))
	s.Int(int64(v.FreqDomainPosition))
	s.Bool(v.GroupHoppingEnabled)
	s.Uint(uint64(v.groupHoppingEnabledRaw))
	{
		f := s.Begin()
		s.Bool(v.DeltaSS == nil)
		if v.DeltaSS != nil {
			s.Int(int64((*v.DeltaSS)))
		}
		s.End(f, q4.Snapshot{}, false)
	}
	q8.BridgeCompareLPPaSFNInitialisationTime(&v.SfnInitialisationTime, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSubframeallocation(v *Subframeallocation, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case q6.SubframeallocationChoiceOneFrame:
		{
			f := s.Begin()
			s.Bool(v.OneFrame == nil)
			if v.OneFrame != nil {
				s.BitString((*v.OneFrame).Bytes, (*v.OneFrame).BitLength)
			}
			s.End(f, nil, false)
		}
	case q6.SubframeallocationChoiceFourFrames:
		{
			f := s.Begin()
			s.Bool(v.FourFrames == nil)
			if v.FourFrames != nil {
				s.BitString((*v.FourFrames).Bytes, (*v.FourFrames).BitLength)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSubframeallocation(v *Subframeallocation, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case q6.SubframeallocationChoiceOneFrame:
		{
			f := s.Begin()
			s.Bool(v.OneFrame == nil)
			if v.OneFrame != nil {
				s.BitString((*v.OneFrame).Bytes, (*v.OneFrame).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q6.SubframeallocationChoiceFourFrames:
		{
			f := s.Begin()
			s.Bool(v.FourFrames == nil)
			if v.FourFrames != nil {
				s.BitString((*v.FourFrames).Bytes, (*v.FourFrames).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationRequestIEValue(v *UTDOAInformationRequestIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q6.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q6.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedSRSTransmissionCharacteristics == nil)
				if v.rowRequestedSRSTransmissionCharacteristics != nil {
					q10.BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(v.rowRequestedSRSTransmissionCharacteristics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationRequestIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v UTDOAInformationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationRequestIEValue) captureSemantics(s q4.SemanticCapture) UTDOAInformationRequestIEValue {
	BridgeCaptureLPPaUTDOAInformationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationRequestIEValue(v *UTDOAInformationRequestIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q6.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedSRSTransmissionCharacteristics == nil)
				if v.rowRequestedSRSTransmissionCharacteristics != nil {
					q10.BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v.rowRequestedSRSTransmissionCharacteristics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationRequestIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationRequestIEValue(&v, &s)
	return s
}
func (v UTDOAInformationRequestIEValue) WithoutReplay() UTDOAInformationRequestIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}

type ECIDMeasurementInitiationFailureIEValue struct {
	id                        q6.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowESMLCUEMeasurementID   *q6.MeasurementID
	rowCause                  *q9.Cause
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v ECIDMeasurementInitiationFailureIEValue) matchesID(id q6.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q6.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case q6.ProtocolIEID(0):
		return v.rowCause != nil
	case q6.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementInitiationFailureIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationFailureIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs"}}
}
func (ECIDMeasurementInitiationFailureIEValue) reason(id q6.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q6.ProtocolIEID(2):
		return q4.UnknownSelector
	case q6.ProtocolIEID(0):
		return q4.UnknownSelector
	case q6.ProtocolIEID(1):
		return q4.UnknownSelector
	case q6.ProtocolIEID(3):
		return q4.NotInTable
	case q6.ProtocolIEID(4):
		return q4.NotInTable
	case q6.ProtocolIEID(5):
		return q4.NotInTable
	case q6.ProtocolIEID(6):
		return q4.NotInTable
	case q6.ProtocolIEID(7):
		return q4.NotInTable
	case q6.ProtocolIEID(8):
		return q4.NotInTable
	case q6.ProtocolIEID(9):
		return q4.NotInTable
	case q6.ProtocolIEID(10):
		return q4.NotInTable
	case q6.ProtocolIEID(11):
		return q4.NotInTable
	case q6.ProtocolIEID(12):
		return q4.NotInTable
	case q6.ProtocolIEID(13):
		return q4.NotInTable
	case q6.ProtocolIEID(14):
		return q4.NotInTable
	case q6.ProtocolIEID(15):
		return q4.NotInTable
	case q6.ProtocolIEID(16):
		return q4.NotInTable
	case q6.ProtocolIEID(17):
		return q4.NotInTable
	case q6.ProtocolIEID(18):
		return q4.NotInTable
	case q6.ProtocolIEID(19):
		return q4.NotInTable
	case q6.ProtocolIEID(20):
		return q4.NotInTable
	case q6.ProtocolIEID(21):
		return q4.NotInTable
	case q6.ProtocolIEID(22):
		return q4.NotInTable
	case q6.ProtocolIEID(23):
		return q4.NotInTable
	case q6.ProtocolIEID(24):
		return q4.NotInTable
	case q6.ProtocolIEID(25):
		return q4.NotInTable
	case q6.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *ECIDMeasurementInitiationFailureIEValue) AsESMLCUEMeasurementID() (*q6.MeasurementID, bool) {
	if v == nil || v.id != q6.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementInitiationFailureIEValue) AsCause() (*q9.Cause, bool) {
	if v == nil || v.id != q6.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *ECIDMeasurementInitiationFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != q6.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ECIDMeasurementInitiationFailureIEValue) decode(id q6.ProtocolIEID, raw q4.OpaqueOpenType) (ECIDMeasurementInitiationFailureIEValue, error) {
	out := ECIDMeasurementInitiationFailureIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 2, 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q6.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q6.BridgeAsn1IntegerBound2, q6.BridgeAsn1IntegerBound7, true)
		value := q6.MeasurementID(decoded)
		if err != nil {
			return out, q5.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q6.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value q9.Cause
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q5.Errorf("%s %w", "Cause:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*q9.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*q9.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCauseFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q6.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q5.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
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
func (v ECIDMeasurementInitiationFailureIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationFailureIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q6.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, q5.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, q6.BridgeAsn1IntegerBound2, q6.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q6.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, q5.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-Cause:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q6.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q5.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowCriticalityDiagnostics.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q5.Errorf("%s id %d has no value", "ECIDMeasurementInitiationFailureIEValue:", v.id)
	}
}

type UTDOAInformationRequestIEValue struct {
	id                                         q6.ProtocolIEID
	withoutReplay                              bool
	received                                   q4.WireSpan
	replay                                     q4.Snapshot
	opaque                                     *q4.OpaqueOpenType
	isOpaque                                   bool
	rowRequestedSRSTransmissionCharacteristics *q10.RequestedSRSTransmissionCharacteristics
}

func (v UTDOAInformationRequestIEValue) matchesID(id q6.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q6.ProtocolIEID(12):
		return v.rowRequestedSRSTransmissionCharacteristics != nil
	default:
		return false
	}
}
func (v *UTDOAInformationRequestIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationRequestIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs"}}
}
func (UTDOAInformationRequestIEValue) reason(id q6.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q6.ProtocolIEID(12):
		return q4.UnknownSelector
	case q6.ProtocolIEID(0):
		return q4.NotInTable
	case q6.ProtocolIEID(1):
		return q4.NotInTable
	case q6.ProtocolIEID(2):
		return q4.NotInTable
	case q6.ProtocolIEID(3):
		return q4.NotInTable
	case q6.ProtocolIEID(4):
		return q4.NotInTable
	case q6.ProtocolIEID(5):
		return q4.NotInTable
	case q6.ProtocolIEID(6):
		return q4.NotInTable
	case q6.ProtocolIEID(7):
		return q4.NotInTable
	case q6.ProtocolIEID(8):
		return q4.NotInTable
	case q6.ProtocolIEID(9):
		return q4.NotInTable
	case q6.ProtocolIEID(10):
		return q4.NotInTable
	case q6.ProtocolIEID(11):
		return q4.NotInTable
	case q6.ProtocolIEID(13):
		return q4.NotInTable
	case q6.ProtocolIEID(14):
		return q4.NotInTable
	case q6.ProtocolIEID(15):
		return q4.NotInTable
	case q6.ProtocolIEID(16):
		return q4.NotInTable
	case q6.ProtocolIEID(17):
		return q4.NotInTable
	case q6.ProtocolIEID(18):
		return q4.NotInTable
	case q6.ProtocolIEID(19):
		return q4.NotInTable
	case q6.ProtocolIEID(20):
		return q4.NotInTable
	case q6.ProtocolIEID(21):
		return q4.NotInTable
	case q6.ProtocolIEID(22):
		return q4.NotInTable
	case q6.ProtocolIEID(23):
		return q4.NotInTable
	case q6.ProtocolIEID(24):
		return q4.NotInTable
	case q6.ProtocolIEID(25):
		return q4.NotInTable
	case q6.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *UTDOAInformationRequestIEValue) AsRequestedSRSTransmissionCharacteristics() (*q10.RequestedSRSTransmissionCharacteristics, bool) {
	if v == nil || v.id != q6.ProtocolIEID(12) || v.rowRequestedSRSTransmissionCharacteristics == nil {
		return nil, false
	}
	return v.rowRequestedSRSTransmissionCharacteristics, true
}
func (v UTDOAInformationRequestIEValue) decode(id q6.ProtocolIEID, raw q4.OpaqueOpenType) (UTDOAInformationRequestIEValue, error) {
	out := UTDOAInformationRequestIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 12:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q6.ProtocolIEID(12):
		replayUsage := scope.Usage()
		var value q10.RequestedSRSTransmissionCharacteristics
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q5.Errorf("%s %w", "RequestedSRSTransmissionCharacteristics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "RequestedSRSTransmissionCharacteristics")
		if err != nil {
			return out, err
		}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsFieldPerPadding(&value) = padding
		*q10.BridgeRequestedSRSTransmissionCharacteristicsFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeRequestedSRSTransmissionCharacteristicsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowRequestedSRSTransmissionCharacteristics = &value
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
func (v UTDOAInformationRequestIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationRequestIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q6.ProtocolIEID(12):
		if v.rowRequestedSRSTransmissionCharacteristics == nil {
			return nil, q5.Errorf("%s missing value", "UTDOAInformationRequest-IEs.id-RequestedSRSTransmissionCharacteristics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERBudget(v.rowRequestedSRSTransmissionCharacteristics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q5.Errorf("%s id %d has no value", "UTDOAInformationRequestIEValue:", v.id)
	}
}

type UTDOAInformationRequestIETable struct{}

func UTDOAInformationRequestIEs() UTDOAInformationRequestIETable {
	return UTDOAInformationRequestIETable{}
}
func (UTDOAInformationRequestIETable) ID() q6.TableID {
	return func() q6.TableID {
		sealed := q6.TableID{}
		*q6.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs"}
		return sealed
	}()
}
func (UTDOAInformationRequestIETable) infoRequestedSRSTransmissionCharacteristics() q6.FieldInfo {
	return q6.FieldInfo{Table: UTDOAInformationRequestIEs().ID(), ID: q6.ProtocolIEID(12), Criticality: q6.CriticalityIgnore, Presence: q6.PresenceOptional, ValueType: func() q6.TypeID {
		sealed := q6.TypeID{}
		*q6.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "RequestedSRSTransmissionCharacteristics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs", Row: "id-RequestedSRSTransmissionCharacteristics"}}}
}
func (t UTDOAInformationRequestIETable) RequestedSRSTransmissionCharacteristics() UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding {
	return UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding{info: t.infoRequestedSRSTransmissionCharacteristics(), codec: func() q10.RequestedSRSTransmissionCharacteristicsValueCodec {
		sealed := q10.RequestedSRSTransmissionCharacteristicsValueCodec{}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldPath(&sealed) = "RequestedSRSTransmissionCharacteristics"
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.RequestedSRSTransmissionCharacteristics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.RequestedSRSTransmissionCharacteristics
				return empty, err
			}
			var zero UTDOAInformationRequestIEValue
			decoded, err := zero.decode(q6.ProtocolIEID(12), raw)
			if err != nil {
				var empty q10.RequestedSRSTransmissionCharacteristics
				return empty, err
			}
			value, ok := decoded.AsRequestedSRSTransmissionCharacteristics()
			if !ok {
				var empty q10.RequestedSRSTransmissionCharacteristics
				return empty, q5.Errorf("binding UTDOAInformationRequest-IEs.id-RequestedSRSTransmissionCharacteristics: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(&sealed) = func(value q10.RequestedSRSTransmissionCharacteristics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationRequestIEValue{id: q6.ProtocolIEID(12), rowRequestedSRSTransmissionCharacteristics: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCapture(&sealed) = func(v q10.RequestedSRSTransmissionCharacteristics, options q4.DecodeState) (q10.RequestedSRSTransmissionCharacteristics, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()

			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCompare(&sealed) = func(v q10.RequestedSRSTransmissionCharacteristics, root q4.Snapshot, limits q4.ComparisonLimits,
		) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q10.BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(&v, &s)

			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldContext(&sealed) = func() q6.BridgeCodecContext {
			sealed := q6.BridgeCodecContext{}
			*q6.BridgecodecContextFieldSource(&sealed) = "source-value:RequestedSRSTransmissionCharacteristics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.RequestedSRSTransmissionCharacteristics) UTDOAInformationRequestIEValue {
			return UTDOAInformationRequestIEValue{id: q6.ProtocolIEID(12), rowRequestedSRSTransmissionCharacteristics: &value}
		}, get: func(value *UTDOAInformationRequestIEValue) (*q10.RequestedSRSTransmissionCharacteristics, bool) {
			return value.AsRequestedSRSTransmissionCharacteristics()
		}}
}
func (t UTDOAInformationRequestIETable) NewOpaque(id q6.ProtocolIEID, criticality q6.Criticality, data []byte) (UTDOAInformationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationRequestIEField{}, q4.OperationError(q5.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q6.ProtocolIEID(12):
		return UTDOAInformationRequestIEField{}, q4.OperationError(q5.Errorf("known IE id-RequestedSRSTransmissionCharacteristics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return UTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		return UTDOAInformationRequestIEField{Id: id, Criticality: criticality, Value: UTDOAInformationRequestIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// MBSFNsubframeConfigurationValueCodec binds the complete source value type.
func MBSFNsubframeConfigurationValueCodec() MBSFNsubframeConfigurationValueValueCodec {
	return MBSFNsubframeConfigurationValueValueCodec{path: "MBSFNsubframeConfigurationValue", decode: func(data []byte, options q4.DecodeState) (MBSFNsubframeConfigurationValue, error) {
		var value MBSFNsubframeConfigurationValue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MBSFNsubframeConfigurationValue{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value MBSFNsubframeConfigurationValue, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MBSFNsubframeConfigurationValue, options q4.DecodeState) (MBSFNsubframeConfigurationValue, q4.Snapshot,
	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaMBSFNsubframeConfigurationValue(&v, &s)
		var root q4.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MBSFNsubframeConfigurationValue, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaMBSFNsubframeConfigurationValue(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNsubframeConfigurationValue"
		return sealed
	}(),
	}
}

// RequestedSRSTransmissionCharacteristicsCodec binds the complete APER value type.
func RequestedSRSTransmissionCharacteristicsCodec() q10.RequestedSRSTransmissionCharacteristicsValueCodec {
	return UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Codec()
}

// SRSConfigurationForOneCellCodec binds the complete source value type.
func SRSConfigurationForOneCellCodec() SRSConfigurationForOneCellValueCodec {
	return SRSConfigurationForOneCellValueCodec{path: "SRSConfigurationForOneCell", decode: func(data []byte, options q4.DecodeState) (SRSConfigurationForOneCell, error) {
		var value SRSConfigurationForOneCell
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SRSConfigurationForOneCell{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value SRSConfigurationForOneCell, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SRSConfigurationForOneCell, options q4.DecodeState) (SRSConfigurationForOneCell, q4.Snapshot,
	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSRSConfigurationForOneCell(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SRSConfigurationForOneCell, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSRSConfigurationForOneCell(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:SRSConfigurationForOneCell"
		return sealed
	}(),
	}
}

// SubframeallocationCodec binds the complete source value type.
func SubframeallocationCodec() SubframeallocationValueCodec {
	return SubframeallocationValueCodec{path: "Subframeallocation", decode: func(data []byte, options q4.DecodeState) (Subframeallocation, error) {
		var value Subframeallocation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return Subframeallocation{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value Subframeallocation, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v Subframeallocation, options q4.DecodeState) (Subframeallocation, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSubframeallocation(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f,
			&root,
			false)
		return v, root
	}, compare: func(v Subframeallocation, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSubframeallocation(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q6.BridgeCodecContext {
		sealed := q6.BridgeCodecContext{}
		*q6.BridgecodecContextFieldSource(&sealed) = "source-value:Subframeallocation"
		return sealed
	}(),
	}
}
func (r *ValidationReport) addIssue(issue ValidationIssue) {
	if err := r.reserveReport(issue.Location); err != nil {
		return
	}
	r.Issues = append(r.Issues, issue)
}
func (r *ValidationReport) addDeferred(item q6.DeferredCondition) {
	if err := r.reserveReport(item.Location); err != nil {
		return
	}
	r.Deferred = append(r.Deferred, item)
}
func (r *ValidationReport) addUnchecked(location q4.Location) {
	if err := r.reserveReport(location); err != nil {
		return
	}
	r.Unchecked = append(r.Unchecked, location)
}
func (r *ValidationReport) reserveReport(location q4.Location) error {
	if r.err != nil {
		return r.err
	}
	if r.budget == nil {
		return nil
	}
	bb := q4.NewBudgetBuffer(r.budget)
	if err := bb.ChargeLocatedReport(location, 1024); err != nil {
		r.err = err
		return err
	}
	return nil
}

type ValidationIssue struct {
	Code                q6.ValidationCode
	Severity            q6.ValidationSeverity
	Location            q4.Location
	Table               q6.TableID
	IEID                q6.ProtocolIEID
	HasIEID             bool
	PrivateID           *q10.PrivateIEID
	ExpectedCriticality *q6.Criticality
	ReceivedCriticality *q6.Criticality
	Rule                q4.SourceRule
	RelatedRules        []q4.SourceRule
}
type ValidationReport struct {
	budget    *q4.DecodeBudget
	err       error
	Issues    []ValidationIssue
	Deferred  []q6.DeferredCondition
	Unchecked []q4.Location
	Complete  bool
}

func BridgeCriticalityDiagnosticsAPERValueFieldContext(v *CriticalityDiagnosticsAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsAPERValueFieldReceived(v *CriticalityDiagnosticsAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsAPERValueFieldReplay(v *CriticalityDiagnosticsAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsAPERValueFieldWithoutReplay(v *CriticalityDiagnosticsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsFieldExtCount(v *CriticalityDiagnostics) *int64   { return &v.extCount }
func BridgeCriticalityDiagnosticsFieldExtData(v *CriticalityDiagnostics) *[][]byte { return &v.extData }
func BridgeCriticalityDiagnosticsFieldExtOrigin(v *CriticalityDiagnostics) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeCriticalityDiagnosticsFieldExtPresent(v *CriticalityDiagnostics) *[]bool {
	return &v.extPresent
}
func BridgeCriticalityDiagnosticsFieldExtWire(v *CriticalityDiagnostics) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeCriticalityDiagnosticsFieldIEExtensionsIndef(v *CriticalityDiagnostics) *bool {
	return &v.iEExtensionsIndef
}
func BridgeCriticalityDiagnosticsFieldIEsCriticalityDiagnosticsIndef(v *CriticalityDiagnostics) *bool {
	return &v.iEsCriticalityDiagnosticsIndef
}
func BridgeCriticalityDiagnosticsFieldPerExtPadding(v *CriticalityDiagnostics) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeCriticalityDiagnosticsFieldPerPadding(v *CriticalityDiagnostics) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsFieldReceived(v *CriticalityDiagnostics) *bool { return &v.received }
func BridgeCriticalityDiagnosticsFieldReceivedBytes(v *CriticalityDiagnostics) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsFieldReplay(v *CriticalityDiagnostics) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsFieldStream(v *CriticalityDiagnostics) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsFieldWithoutReplay(v *CriticalityDiagnostics) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v *CriticalityDiagnostics, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERChanged(v *CriticalityDiagnostics, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERChangedValue(v *CriticalityDiagnostics, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERFreshValue(v *CriticalityDiagnostics, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERLegacy(v *CriticalityDiagnostics) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERPlanned(v *CriticalityDiagnostics, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERTo(v *CriticalityDiagnostics, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(v *CriticalityDiagnostics, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERLegacy(v *CriticalityDiagnostics, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsMethodUnmarshalAPERWithOptions(v *CriticalityDiagnostics, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCriticalityDiagnosticsValueCodecFieldCapture(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, q4.DecodeState) (CriticalityDiagnostics, q4.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsValueCodecFieldCompare(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityDiagnosticsValueCodecFieldContext(v *CriticalityDiagnosticsValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsValueCodecFieldDecode(v *CriticalityDiagnosticsValueCodec) *func([]byte, q4.DecodeState) (CriticalityDiagnostics, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsValueCodecFieldEncode(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsValueCodecFieldPath(v *CriticalityDiagnosticsValueCodec) *q4.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeBudget(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeChanged(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureCauseIEBinding) *q9.CauseValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldGet(v *ECIDMeasurementInitiationFailureCauseIEBinding) *func(*ECIDMeasurementInitiationFailureIEValue) (*q9.Cause, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureCauseIEBinding) *q6.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInject(v *ECIDMeasurementInitiationFailureCauseIEBinding) *func(q9.Cause) ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldGet(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *func(*ECIDMeasurementInitiationFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *q6.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInject(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldReceived(v *ECIDMeasurementInitiationFailureIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v *ECIDMeasurementInitiationFailureIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldStream(v *ECIDMeasurementInitiationFailureIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationFailureIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationFailureIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationFailureIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldId(v *ECIDMeasurementInitiationFailureIEValue) *q6.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldIsOpaque(v *ECIDMeasurementInitiationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldOpaque(v *ECIDMeasurementInitiationFailureIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldReceived(v *ECIDMeasurementInitiationFailureIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldReplay(v *ECIDMeasurementInitiationFailureIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(v *ECIDMeasurementInitiationFailureIEValue) **q9.Cause {
	return &v.rowCause
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(v *ECIDMeasurementInitiationFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationFailureIEValue) **q6.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldWithoutReplay(v *ECIDMeasurementInitiationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureFraming(v ECIDMeasurementInitiationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationFailureIEValue, a0 q4.SemanticCapture) ECIDMeasurementInitiationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationFailureIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCompareSemantics(v ECIDMeasurementInitiationFailureIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(v ECIDMeasurementInitiationFailureIEValue, a0 q6.ProtocolIEID, a1 q4.OpaqueOpenType) (ECIDMeasurementInitiationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodEncode(v ECIDMeasurementInitiationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh(v ECIDMeasurementInitiationFailureIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodMatchesID(v ECIDMeasurementInitiationFailureIEValue, a0 q6.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodReason(v ECIDMeasurementInitiationFailureIEValue, a0 q6.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodRule(v ECIDMeasurementInitiationFailureIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldContext(v *MBSFNsubframeConfigurationAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldReceived(v *MBSFNsubframeConfigurationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldReplay(v *MBSFNsubframeConfigurationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldWithoutReplay(v *MBSFNsubframeConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCapture(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, q4.DecodeState) (MBSFNsubframeConfiguration, q4.Snapshot) {
	return &v.capture
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCompare(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldContext(v *MBSFNsubframeConfigurationConcreteValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldDecode(v *MBSFNsubframeConfigurationConcreteValueCodec) *func([]byte, q4.DecodeState) (MBSFNsubframeConfiguration, error) {
	return &v.decode
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldEncode(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldPath(v *MBSFNsubframeConfigurationConcreteValueCodec) *q4.Path {
	return &v.path
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecMethodEncodeBudget(v MBSFNsubframeConfigurationConcreteValueCodec, a0 MBSFNsubframeConfiguration, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecMethodEncodeChanged(v MBSFNsubframeConfigurationConcreteValueCodec, a0 MBSFNsubframeConfiguration, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldContext(v *MBSFNsubframeConfigurationValueAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldReceived(v *MBSFNsubframeConfigurationValueAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldReplay(v *MBSFNsubframeConfigurationValueAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldWithoutReplay(v *MBSFNsubframeConfigurationValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationValueFieldPerPadding(v *MBSFNsubframeConfigurationValue) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeMBSFNsubframeConfigurationValueFieldReceived(v *MBSFNsubframeConfigurationValue) *bool {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationValueFieldReceivedBytes(v *MBSFNsubframeConfigurationValue) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNsubframeConfigurationValueFieldReplay(v *MBSFNsubframeConfigurationValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationValueFieldStream(v *MBSFNsubframeConfigurationValue) *q4.WireSpan {
	return &v.stream
}
func BridgeMBSFNsubframeConfigurationValueFieldWithoutReplay(v *MBSFNsubframeConfigurationValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERBudget(v *MBSFNsubframeConfigurationValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERChanged(v *MBSFNsubframeConfigurationValue, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERChangedValue(v *MBSFNsubframeConfigurationValue, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERFreshValue(v *MBSFNsubframeConfigurationValue, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERLegacy(v *MBSFNsubframeConfigurationValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERPlanned(v *MBSFNsubframeConfigurationValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(v *MBSFNsubframeConfigurationValue, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(v *MBSFNsubframeConfigurationValue, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERLegacy(v *MBSFNsubframeConfigurationValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERWithOptions(v *MBSFNsubframeConfigurationValue, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldCapture(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, q4.DecodeState) (MBSFNsubframeConfigurationValue, q4.Snapshot) {
	return &v.capture
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldCompare(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldContext(v *MBSFNsubframeConfigurationValueValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldDecode(v *MBSFNsubframeConfigurationValueValueCodec) *func([]byte, q4.DecodeState) (MBSFNsubframeConfigurationValue, error) {
	return &v.decode
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldEncode(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldPath(v *MBSFNsubframeConfigurationValueValueCodec) *q4.Path {
	return &v.path
}
func BridgeMBSFNsubframeConfigurationValueValueCodecMethodEncodeBudget(v MBSFNsubframeConfigurationValueValueCodec, a0 MBSFNsubframeConfigurationValue, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueValueCodecMethodEncodeChanged(v MBSFNsubframeConfigurationValueValueCodec, a0 MBSFNsubframeConfigurationValue, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldContext(v *SRSConfigurationForAllCellsAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldReceived(v *SRSConfigurationForAllCellsAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldReplay(v *SRSConfigurationForAllCellsAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldWithoutReplay(v *SRSConfigurationForAllCellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldCapture(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, q4.DecodeState) (SRSConfigurationForAllCells, q4.Snapshot) {
	return &v.capture
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldCompare(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldContext(v *SRSConfigurationForAllCellsValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldDecode(v *SRSConfigurationForAllCellsValueCodec) *func([]byte, q4.DecodeState) (SRSConfigurationForAllCells, error) {
	return &v.decode
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldEncode(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldPath(v *SRSConfigurationForAllCellsValueCodec) *q4.Path {
	return &v.path
}
func BridgeSRSConfigurationForAllCellsValueCodecMethodEncodeBudget(v SRSConfigurationForAllCellsValueCodec, a0 SRSConfigurationForAllCells, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsValueCodecMethodEncodeChanged(v SRSConfigurationForAllCellsValueCodec, a0 SRSConfigurationForAllCells, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSRSConfigurationForOneCellAPERValueFieldContext(v *SRSConfigurationForOneCellAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForOneCellAPERValueFieldReceived(v *SRSConfigurationForOneCellAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeSRSConfigurationForOneCellAPERValueFieldReplay(v *SRSConfigurationForOneCellAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForOneCellAPERValueFieldWithoutReplay(v *SRSConfigurationForOneCellAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForOneCellFieldExtCount(v *SRSConfigurationForOneCell) *int64 {
	return &v.extCount
}
func BridgeSRSConfigurationForOneCellFieldExtData(v *SRSConfigurationForOneCell) *[][]byte {
	return &v.extData
}
func BridgeSRSConfigurationForOneCellFieldExtOrigin(v *SRSConfigurationForOneCell) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSRSConfigurationForOneCellFieldExtPresent(v *SRSConfigurationForOneCell) *[]bool {
	return &v.extPresent
}
func BridgeSRSConfigurationForOneCellFieldExtWire(v *SRSConfigurationForOneCell) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeSRSConfigurationForOneCellFieldGroupHoppingEnabledRaw(v *SRSConfigurationForOneCell) *byte {
	return &v.groupHoppingEnabledRaw
}
func BridgeSRSConfigurationForOneCellFieldPerExtPadding(v *SRSConfigurationForOneCell) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeSRSConfigurationForOneCellFieldPerPadding(v *SRSConfigurationForOneCell) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeSRSConfigurationForOneCellFieldReceived(v *SRSConfigurationForOneCell) *bool {
	return &v.received
}
func BridgeSRSConfigurationForOneCellFieldReceivedBytes(v *SRSConfigurationForOneCell) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeSRSConfigurationForOneCellFieldReplay(v *SRSConfigurationForOneCell) *q4.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForOneCellFieldStream(v *SRSConfigurationForOneCell) *q4.WireSpan {
	return &v.stream
}
func BridgeSRSConfigurationForOneCellFieldWithoutReplay(v *SRSConfigurationForOneCell) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERBudget(v *SRSConfigurationForOneCell, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERChanged(v *SRSConfigurationForOneCell, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERChangedValue(v *SRSConfigurationForOneCell, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERFreshValue(v *SRSConfigurationForOneCell, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERLegacy(v *SRSConfigurationForOneCell) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERPlanned(v *SRSConfigurationForOneCell, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(v *SRSConfigurationForOneCell, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(v *SRSConfigurationForOneCell, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERLegacy(v *SRSConfigurationForOneCell, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERWithOptions(v *SRSConfigurationForOneCell, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSRSConfigurationForOneCellValueCodecFieldCapture(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, q4.DecodeState) (SRSConfigurationForOneCell, q4.Snapshot) {
	return &v.capture
}
func BridgeSRSConfigurationForOneCellValueCodecFieldCompare(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeSRSConfigurationForOneCellValueCodecFieldContext(v *SRSConfigurationForOneCellValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForOneCellValueCodecFieldDecode(v *SRSConfigurationForOneCellValueCodec) *func([]byte, q4.DecodeState) (SRSConfigurationForOneCell, error) {
	return &v.decode
}
func BridgeSRSConfigurationForOneCellValueCodecFieldEncode(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRSConfigurationForOneCellValueCodecFieldPath(v *SRSConfigurationForOneCellValueCodec) *q4.Path {
	return &v.path
}
func BridgeSRSConfigurationForOneCellValueCodecMethodEncodeBudget(v SRSConfigurationForOneCellValueCodec, a0 SRSConfigurationForOneCell, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellValueCodecMethodEncodeChanged(v SRSConfigurationForOneCellValueCodec, a0 SRSConfigurationForOneCell, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSubframeallocationAPERValueFieldContext(v *SubframeallocationAPERValue) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSubframeallocationAPERValueFieldReceived(v *SubframeallocationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeSubframeallocationAPERValueFieldReplay(v *SubframeallocationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSubframeallocationAPERValueFieldWithoutReplay(v *SubframeallocationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSubframeallocationFieldPerOpenTypePadding(v *Subframeallocation) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSubframeallocationFieldPerPadding(v *Subframeallocation) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeSubframeallocationFieldReceived(v *Subframeallocation) *bool { return &v.received }
func BridgeSubframeallocationFieldReceivedBytes(v *Subframeallocation) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeSubframeallocationFieldReplay(v *Subframeallocation) *q4.Snapshot { return &v.replay }
func BridgeSubframeallocationFieldStream(v *Subframeallocation) *q4.WireSpan { return &v.stream }
func BridgeSubframeallocationFieldWithoutReplay(v *Subframeallocation) *bool { return &v.withoutReplay }
func BridgeSubframeallocationMethodMarshalAPERBudget(v *Subframeallocation, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERChanged(v *Subframeallocation, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSubframeallocationMethodMarshalAPERChangedValue(v *Subframeallocation, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSubframeallocationMethodMarshalAPERFreshValue(v *Subframeallocation, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERLegacy(v *Subframeallocation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSubframeallocationMethodMarshalAPERPlanned(v *Subframeallocation, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERTo(v *Subframeallocation, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSubframeallocationMethodUnmarshalAPERFrom(v *Subframeallocation, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSubframeallocationMethodUnmarshalAPERLegacy(v *Subframeallocation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSubframeallocationMethodUnmarshalAPERWithOptions(v *Subframeallocation, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSubframeallocationValueCodecFieldCapture(v *SubframeallocationValueCodec) *func(Subframeallocation, q4.DecodeState) (Subframeallocation, q4.Snapshot) {
	return &v.capture
}
func BridgeSubframeallocationValueCodecFieldCompare(v *SubframeallocationValueCodec) *func(Subframeallocation, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeSubframeallocationValueCodecFieldContext(v *SubframeallocationValueCodec) *q6.BridgeCodecContext {
	return &v.context
}
func BridgeSubframeallocationValueCodecFieldDecode(v *SubframeallocationValueCodec) *func([]byte, q4.DecodeState) (Subframeallocation, error) {
	return &v.decode
}
func BridgeSubframeallocationValueCodecFieldEncode(v *SubframeallocationValueCodec) *func(Subframeallocation, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubframeallocationValueCodecFieldPath(v *SubframeallocationValueCodec) *q4.Path {
	return &v.path
}
func BridgeSubframeallocationValueCodecMethodEncodeBudget(v SubframeallocationValueCodec, a0 Subframeallocation, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSubframeallocationValueCodecMethodEncodeChanged(v SubframeallocationValueCodec, a0 Subframeallocation, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationRequestIEFieldFieldReceived(v *UTDOAInformationRequestIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationRequestIEFieldFieldReplay(v *UTDOAInformationRequestIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestIEFieldFieldStream(v *UTDOAInformationRequestIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v *UTDOAInformationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestIEFieldMethodMarshalAPERTo(v *UTDOAInformationRequestIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationRequestIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationRequestIETableMethodInfoRequestedSRSTransmissionCharacteristics(v UTDOAInformationRequestIETable) q6.FieldInfo {
	return v.infoRequestedSRSTransmissionCharacteristics()
}
func BridgeUTDOAInformationRequestIEValueFieldId(v *UTDOAInformationRequestIEValue) *q6.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationRequestIEValueFieldIsOpaque(v *UTDOAInformationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationRequestIEValueFieldOpaque(v *UTDOAInformationRequestIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationRequestIEValueFieldReceived(v *UTDOAInformationRequestIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationRequestIEValueFieldReplay(v *UTDOAInformationRequestIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestIEValueFieldRowRequestedSRSTransmissionCharacteristics(v *UTDOAInformationRequestIEValue) **q10.RequestedSRSTransmissionCharacteristics {
	return &v.rowRequestedSRSTransmissionCharacteristics
}
func BridgeUTDOAInformationRequestIEValueFieldWithoutReplay(v *UTDOAInformationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureFraming(v UTDOAInformationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureSemantics(v UTDOAInformationRequestIEValue, a0 q4.SemanticCapture) UTDOAInformationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureSnapshot(v UTDOAInformationRequestIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationRequestIEValueMethodCompareSemantics(v UTDOAInformationRequestIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodDecode(v UTDOAInformationRequestIEValue, a0 q6.ProtocolIEID, a1 q4.OpaqueOpenType) (UTDOAInformationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodEncode(v UTDOAInformationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationRequestIEValueMethodEncodeFresh(v UTDOAInformationRequestIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodMatchesID(v UTDOAInformationRequestIEValue, a0 q6.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodReason(v UTDOAInformationRequestIEValue, a0 q6.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodRule(v UTDOAInformationRequestIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldCodec(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *q10.RequestedSRSTransmissionCharacteristicsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldGet(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *func(*UTDOAInformationRequestIEValue) (*q10.RequestedSRSTransmissionCharacteristics, bool) {
	return &v.get
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldInfo(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *q6.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldInject(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *func(q10.RequestedSRSTransmissionCharacteristics) UTDOAInformationRequestIEValue {
	return &v.inject
}
func BridgeValidationReportFieldBudget(v *ValidationReport) **q4.DecodeBudget { return &v.budget }
func BridgeValidationReportFieldErr(v *ValidationReport) *error               { return &v.err }
func BridgeValidationReportMethodAddDeferred(v *ValidationReport, a0 q6.DeferredCondition) {
	v.addDeferred(a0)
}
func BridgeValidationReportMethodAddIssue(v *ValidationReport, a0 ValidationIssue) { v.addIssue(a0) }
func BridgeValidationReportMethodAddUnchecked(v *ValidationReport, a0 q4.Location) {
	v.addUnchecked(a0)
}
func BridgeValidationReportMethodReserveReport(v *ValidationReport, a0 q4.Location) error {
	return v.reserveReport(a0)
}
