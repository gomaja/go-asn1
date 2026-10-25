// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s09 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s09

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

type BuildError struct{ Issues []ValidationIssue }

// Unwrap returns the invalid-value error associated with a failed build.
func (e *BuildError) Unwrap() error { return aper.ErrInvalidValue }

// Error describes the first blocking message-structure issue.
func (e *BuildError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "LPPa build failed"
	}
	return fmt.Sprintf("LPPa build at %s: structural issue %d (IE %d)", e.Issues[0].Location.Path, e.Issues[0].Code, e.Issues[0].IEID)
}
func BridgeBuildBlockingIssues(report ValidationReport) []ValidationIssue {
	blocking := report.Issues[:0]
	for _, issue := range report.Issues {
		if report.budget != nil {
			if err := aper.NewBudgetBuffer(report.budget).ChargeWork(1); err != nil {
				return nil
			}
		}
		if issue.Severity == s00.ValidationSeverityError {
			blocking = append(blocking, issue)
		}
	}
	return blocking
}

// ECIDMeasurementInitiationFailureIEContainer is ProtocolIE-Container {{E-CIDMeasurementInitiationFailure-IEs}} of TS 36.455: a list of ECIDMeasurementInitiationFailureIEField values.
type ECIDMeasurementInitiationFailureIEContainer []ECIDMeasurementInitiationFailureIEField

// ECIDMeasurementInitiationFailureIEField is ProtocolIE-Field {{E-CIDMeasurementInitiationFailure-IEs}} of TS 36.455: a field carrying a value of ECIDMeasurementInitiationFailureIEValue.
type ECIDMeasurementInitiationFailureIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ECIDMeasurementInitiationFailureIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationFailureIEField) WithoutReplay() ECIDMeasurementInitiationFailureIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementInitiationFailureIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationFailureIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementInitiationFailureIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationFailureIEField{}
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
	var zero ECIDMeasurementInitiationFailureIEValue

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

// UTDOAInformationRequestIEContainer is ProtocolIE-Container {{UTDOAInformationRequest-IEs}} of TS 36.455: a list of UTDOAInformationRequestIEField values.
type UTDOAInformationRequestIEContainer []UTDOAInformationRequestIEField

// UTDOAInformationRequestIEField is ProtocolIE-Field {{UTDOAInformationRequest-IEs}} of TS 36.455: a field carrying a value of UTDOAInformationRequestIEValue.
type UTDOAInformationRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UTDOAInformationRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationRequestIEField) WithoutReplay() UTDOAInformationRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *UTDOAInformationRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UTDOAInformationRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationRequestIEField{}
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
	var zero UTDOAInformationRequestIEValue

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

// CriticalityDiagnosticsValueCodec is the concrete ValueCodec[CriticalityDiagnostics].
type CriticalityDiagnosticsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(CriticalityDiagnostics, aper.DecodeState,

	) (CriticalityDiagnostics, aper.Snapshot,

	)
	compare func(CriticalityDiagnostics, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (CriticalityDiagnostics,

		error)
	encode func(CriticalityDiagnostics,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c CriticalityDiagnosticsValueCodec) New(value CriticalityDiagnostics,

) (CriticalityDiagnosticsAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return CriticalityDiagnosticsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c CriticalityDiagnosticsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityDiagnosticsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return CriticalityDiagnosticsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityDiagnosticsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityDiagnosticsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return CriticalityDiagnosticsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c CriticalityDiagnosticsValueCodec) EncodeAPER(value CriticalityDiagnosticsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsValueCodec) encodeBudget(value CriticalityDiagnostics,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityDiagnosticsValueCodec) encodeChanged(value CriticalityDiagnostics,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECIDMeasurementInitiationFailureCauseIEBinding binds Cause to ProtocolIE-Field {{E-CIDMeasurementInitiationFailure-IEs}} of TS 36.455.
type ECIDMeasurementInitiationFailureCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s05.CauseValueCodec
	inject func(s05.Cause,

	) ECIDMeasurementInitiationFailureIEValue

	get func(*ECIDMeasurementInitiationFailureIEValue,

	) (*s05.Cause,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationFailureCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationFailureCauseIEBinding) Codec() s05.CauseValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationFailureCauseIEBinding) New(value s05.Cause,

) (ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationFailureCauseIEBinding) Get(field *ECIDMeasurementInitiationFailureIEField) (*s05.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{E-CIDMeasurementInitiationFailure-IEs}} of TS 36.455.
type ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  CriticalityDiagnosticsValueCodec
	inject func(CriticalityDiagnostics,

	) ECIDMeasurementInitiationFailureIEValue

	get func(*ECIDMeasurementInitiationFailureIEValue,

	) (*CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Codec() CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) New(value CriticalityDiagnostics,

) (ECIDMeasurementInitiationFailureIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) Get(field *ECIDMeasurementInitiationFailureIEField) (*CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding binds RequestedSRSTransmissionCharacteristics to ProtocolIE-Field {{UTDOAInformationRequest-IEs}} of TS 36.455.
type UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding struct {
	info   s00.FieldInfo
	codec  s08.RequestedSRSTransmissionCharacteristicsValueCodec
	inject func(s08.RequestedSRSTransmissionCharacteristics,

	) UTDOAInformationRequestIEValue

	get func(*UTDOAInformationRequestIEValue,

	) (*s08.RequestedSRSTransmissionCharacteristics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Codec() s08.RequestedSRSTransmissionCharacteristicsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) New(value s08.RequestedSRSTransmissionCharacteristics,

) (UTDOAInformationRequestIEField, error) {
	if b.inject == nil {
		return UTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) Get(field *UTDOAInformationRequestIEField) (*s08.RequestedSRSTransmissionCharacteristics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MBSFNsubframeConfigurationConcreteValueCodec is the concrete ValueCodec[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationConcreteValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MBSFNsubframeConfiguration, aper.DecodeState,

	) (MBSFNsubframeConfiguration, aper.Snapshot,

	)
	compare func(MBSFNsubframeConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MBSFNsubframeConfiguration,

		error)
	encode func(MBSFNsubframeConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MBSFNsubframeConfigurationConcreteValueCodec) New(value MBSFNsubframeConfiguration,

) (MBSFNsubframeConfigurationAPERValue, error) {
	if c.encode == nil {
		return MBSFNsubframeConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MBSFNsubframeConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MBSFNsubframeConfigurationConcreteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNsubframeConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MBSFNsubframeConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MBSFNsubframeConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MBSFNsubframeConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MBSFNsubframeConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MBSFNsubframeConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MBSFNsubframeConfigurationConcreteValueCodec) EncodeAPER(value MBSFNsubframeConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MBSFNsubframeConfigurationConcreteValueCodec) encodeBudget(value MBSFNsubframeConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MBSFNsubframeConfigurationConcreteValueCodec) encodeChanged(value MBSFNsubframeConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// MBSFNsubframeConfigurationValueValueCodec is the concrete ValueCodec[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MBSFNsubframeConfigurationValue, aper.DecodeState,

	) (MBSFNsubframeConfigurationValue, aper.Snapshot,

	)
	compare func(MBSFNsubframeConfigurationValue, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MBSFNsubframeConfigurationValue,

		error)
	encode func(MBSFNsubframeConfigurationValue,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MBSFNsubframeConfigurationValueValueCodec) New(value MBSFNsubframeConfigurationValue,

) (MBSFNsubframeConfigurationValueAPERValue, error) {
	if c.encode == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MBSFNsubframeConfigurationValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MBSFNsubframeConfigurationValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNsubframeConfigurationValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MBSFNsubframeConfigurationValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MBSFNsubframeConfigurationValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MBSFNsubframeConfigurationValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MBSFNsubframeConfigurationValueValueCodec) EncodeAPER(value MBSFNsubframeConfigurationValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MBSFNsubframeConfigurationValueValueCodec) encodeBudget(value MBSFNsubframeConfigurationValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MBSFNsubframeConfigurationValueValueCodec) encodeChanged(value MBSFNsubframeConfigurationValue,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SRSConfigurationForAllCellsValueCodec is the concrete ValueCodec[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(SRSConfigurationForAllCells, aper.DecodeState,

	) (SRSConfigurationForAllCells, aper.Snapshot,

	)
	compare func(SRSConfigurationForAllCells, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (SRSConfigurationForAllCells,

		error)
	encode func(SRSConfigurationForAllCells,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SRSConfigurationForAllCellsValueCodec) New(value SRSConfigurationForAllCells,

) (SRSConfigurationForAllCellsAPERValue, error) {
	if c.encode == nil {
		return SRSConfigurationForAllCellsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SRSConfigurationForAllCellsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SRSConfigurationForAllCellsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SRSConfigurationForAllCellsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SRSConfigurationForAllCellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SRSConfigurationForAllCellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SRSConfigurationForAllCellsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SRSConfigurationForAllCellsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SRSConfigurationForAllCellsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SRSConfigurationForAllCellsValueCodec) EncodeAPER(value SRSConfigurationForAllCellsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SRSConfigurationForAllCellsValueCodec) encodeBudget(value SRSConfigurationForAllCells,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SRSConfigurationForAllCellsValueCodec) encodeChanged(value SRSConfigurationForAllCells,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SRSConfigurationForOneCellValueCodec is the concrete ValueCodec[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellValueCodec struct {
	context s00.BridgeCodecContext
	capture func(SRSConfigurationForOneCell, aper.DecodeState,

	) (SRSConfigurationForOneCell, aper.Snapshot,

	)
	compare func(SRSConfigurationForOneCell, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (SRSConfigurationForOneCell,

		error)
	encode func(SRSConfigurationForOneCell,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SRSConfigurationForOneCellValueCodec) New(value SRSConfigurationForOneCell,

) (SRSConfigurationForOneCellAPERValue, error) {
	if c.encode == nil {
		return SRSConfigurationForOneCellAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SRSConfigurationForOneCellAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRSConfigurationForOneCellAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SRSConfigurationForOneCellAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SRSConfigurationForOneCellValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SRSConfigurationForOneCellAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SRSConfigurationForOneCellAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SRSConfigurationForOneCellAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SRSConfigurationForOneCellAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SRSConfigurationForOneCellAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SRSConfigurationForOneCellAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SRSConfigurationForOneCellValueCodec) EncodeAPER(value SRSConfigurationForOneCellAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SRSConfigurationForOneCellValueCodec) encodeBudget(value SRSConfigurationForOneCell,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SRSConfigurationForOneCellValueCodec) encodeChanged(value SRSConfigurationForOneCell,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SubframeallocationValueCodec is the concrete ValueCodec[Subframeallocation].
type SubframeallocationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(Subframeallocation, aper.DecodeState,

	) (Subframeallocation, aper.Snapshot,

	)
	compare func(Subframeallocation, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (Subframeallocation,

		error)
	encode func(Subframeallocation,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SubframeallocationValueCodec) New(value Subframeallocation,

) (SubframeallocationAPERValue, error) {
	if c.encode == nil {
		return SubframeallocationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubframeallocationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubframeallocationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SubframeallocationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SubframeallocationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubframeallocationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SubframeallocationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SubframeallocationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SubframeallocationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SubframeallocationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SubframeallocationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SubframeallocationValueCodec) EncodeAPER(value SubframeallocationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SubframeallocationValueCodec) encodeBudget(value Subframeallocation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SubframeallocationValueCodec) encodeChanged(value Subframeallocation,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}
func BridgeAddOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields s03.AddOTDOACellsExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.AddOTDOACellsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(s03.AddOTDOACellsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAddOTDOACellsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationExtIEsValueValidateLPPaExtensionContainer(fields s03.AssistanceInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.AssistanceInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(s03.AssistanceInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaExtensionContainer(fields s03.AssistanceInformationFailureListExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.AssistanceInformationFailureListExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(s03.AssistanceInformationFailureListExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaExtensionContainer(fields s03.AssistanceInformationMetaDataExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.AssistanceInformationMetaDataExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return ValidationReport{err: err, budget: budget}
	}
	asIE := make(s03.AssistanceInformationMetaDataExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// CriticalityDiagnosticsAPERValue is the concrete APERValue[CriticalityDiagnostics].
type CriticalityDiagnosticsAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnostics

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v CriticalityDiagnosticsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsAPERValue) WithoutReplay() CriticalityDiagnosticsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNsubframeConfigurationAPERValue is the concrete APERValue[MBSFNsubframeConfiguration].
type MBSFNsubframeConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   MBSFNsubframeConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MBSFNsubframeConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MBSFNsubframeConfigurationAPERValue) WithoutReplay() MBSFNsubframeConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNsubframeConfigurationValueAPERValue is the concrete APERValue[MBSFNsubframeConfigurationValue].
type MBSFNsubframeConfigurationValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   MBSFNsubframeConfigurationValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MBSFNsubframeConfigurationValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MBSFNsubframeConfigurationValueAPERValue) WithoutReplay() MBSFNsubframeConfigurationValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SRSConfigurationForAllCellsAPERValue is the concrete APERValue[SRSConfigurationForAllCells].
type SRSConfigurationForAllCellsAPERValue struct {
	context s00.BridgeCodecContext
	Value   SRSConfigurationForAllCells

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SRSConfigurationForAllCellsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SRSConfigurationForAllCellsAPERValue) WithoutReplay() SRSConfigurationForAllCellsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SRSConfigurationForOneCellAPERValue is the concrete APERValue[SRSConfigurationForOneCell].
type SRSConfigurationForOneCellAPERValue struct {
	context s00.BridgeCodecContext
	Value   SRSConfigurationForOneCell

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SRSConfigurationForOneCellAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SRSConfigurationForOneCellAPERValue) WithoutReplay() SRSConfigurationForOneCellAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SubframeallocationAPERValue is the concrete APERValue[Subframeallocation].
type SubframeallocationAPERValue struct {
	context s00.BridgeCodecContext
	Value   Subframeallocation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SubframeallocationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SubframeallocationAPERValue) WithoutReplay() SubframeallocationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeAddOTDOACellsExtIEsValueValidateLPPaIEContainer(fields s03.AddOTDOACellsExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
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
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeAddOTDOACellsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeAddOTDOACellsExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			report.addDeferred(s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
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
func BridgeAssistanceInformationExtIEsValueValidateLPPaIEContainer(fields s03.AssistanceInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
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
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeAssistanceInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeAssistanceInformationExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			report.addDeferred(s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
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
func BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaIEContainer(fields s03.AssistanceInformationFailureListExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
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
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeAssistanceInformationFailureListExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			report.addDeferred(s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
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
func BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaIEContainer(fields s03.AssistanceInformationMetaDataExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) ValidationReport {
	report := ValidationReport{Complete: true, budget: budget}
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		report.err = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
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
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(field.Value)
			report.addIssue(ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			report.addIssue(ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			report.addIssue(ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			report.addIssue(ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			report.addIssue(ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			report.addIssue(ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			report.addDeferred(s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
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
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	withoutReplay                  bool
	received                       bool
	receivedBytes                  aper.WireSpan
	ProcedureCode                  *s00.ProcedureCode                           `asn1:"tag:0,context,implicit,optional" json:"ProcedureCode,omitempty"`
	TriggeringMessage              *s00.TriggeringMessage                       `asn1:"tag:1,context,implicit,optional" json:"TriggeringMessage,omitempty"`
	ProcedureCriticality           *s00.Criticality                             `asn1:"tag:2,context,implicit,optional" json:"ProcedureCriticality,omitempty"`
	LppatransactionID              *s00.LPPATransactionID                       `asn1:"tag:3,context,implicit,optional" json:"LppatransactionID,omitempty"`
	IEsCriticalityDiagnostics      s05.CriticalityDiagnosticsIEList             `asn1:"tag:4,context,implicit,optional" json:"IEsCriticalityDiagnostics,omitzero"`
	iEsCriticalityDiagnosticsIndef bool                                         `asn1:"-" json:"-"`
	IEExtensions                   s03.CriticalityDiagnosticsExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                         `asn1:"-" json:"-"`
	extCount                       int64                                        `asn1:"-" json:"-"`
	extPresent                     []bool                                       `asn1:"-" json:"-"`
	extData                        [][]byte                                     `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}
type MBSFNsubframeConfiguration = []MBSFNsubframeConfigurationValue

// MBSFNsubframeConfigurationValue represents the ASN.1 type MBSFNsubframeConfigurationValue (SEQUENCE).
type MBSFNsubframeConfigurationValue struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              aper.WireSpan
	RadioframeAllocationPeriod int64                `asn1:"tag:0,context,implicit"`
	RadioframeAllocationOffset int64                `asn1:"tag:1,context,implicit"`
	SubframeAllocation         Subframeallocation   `asn1:"tag:2,context,explicit"`
	perPadding                 aper.CompletePadding `asn1:"-" json:"-"`
}
type SRSConfigurationForAllCells = []SRSConfigurationForOneCell

// SRSConfigurationForOneCell represents the ASN.1 type SRSConfigurationForOneCell (SEQUENCE).
type SRSConfigurationForOneCell struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          aper.WireSpan
	Pci                    s00.PCI                   `asn1:"tag:0,context,implicit"`
	UlEarfcn               s00.EARFCN                `asn1:"tag:1,context,implicit"`
	UlBandwidth            int64                     `asn1:"tag:2,context,implicit"`
	UlCyclicPrefixLength   s00.CPLength              `asn1:"tag:3,context,implicit"`
	SrsBandwidthConfig     int64                     `asn1:"tag:4,context,implicit"`
	SrsBandwidth           int64                     `asn1:"tag:5,context,implicit"`
	SrsAntennaPort         int64                     `asn1:"tag:6,context,implicit"`
	SrsHoppingBandwidth    int64                     `asn1:"tag:7,context,implicit"`
	SrsCyclicShift         int64                     `asn1:"tag:8,context,implicit"`
	SrsConfigIndex         int64                     `asn1:"tag:9,context,implicit"`
	MaxUpPts               *int64                    `asn1:"tag:10,context,implicit,optional" json:"MaxUpPts,omitempty"`
	TransmissionComb       int64                     `asn1:"tag:11,context,implicit"`
	FreqDomainPosition     int64                     `asn1:"tag:12,context,implicit"`
	GroupHoppingEnabled    bool                      `asn1:"tag:13,context,implicit"`
	groupHoppingEnabledRaw byte                      `asn1:"-" json:"-"`
	DeltaSS                *int64                    `asn1:"tag:14,context,implicit,optional" json:"DeltaSS,omitempty"`
	SfnInitialisationTime  s00.SFNInitialisationTime `asn1:"tag:15,context,implicit"`
	extCount               int64                     `asn1:"-" json:"-"`
	extPresent             []bool                    `asn1:"-" json:"-"`
	extData                [][]byte                  `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// Subframeallocation represents the ASN.1 CHOICE type Subframeallocation.
type Subframeallocation struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding `json:"-"`
	perOpenTypePadding aper.CompletePadding `json:"-"`
	OneFrame           *runtime.BitString   `json:"OneFrame,omitempty"`
	FourFrames         *runtime.BitString   `json:"FourFrames,omitempty"`
}
type BridgeAsn1cAPERAssistanceInformationFailureListListValue struct {
	Value s05.AssistanceInformationFailureList
}

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
	if err := aper.EncodeBoolean(bb, v.ProcedureCode != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.TriggeringMessage != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ProcedureCriticality != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.LppatransactionID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEsCriticalityDiagnostics != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ProcedureCode != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ProcedureCode), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
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
	if v.LppatransactionID != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.LppatransactionID), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
			return fmt.Errorf("encoding lppatransactionID: %w", err)
		}
	}
	if v.IEsCriticalityDiagnostics != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEsCriticalityDiagnostics)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentOffset_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics)) || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(len(v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEsCriticalityDiagnostics[fragmentOffset_iescriticalitydiagnostics : fragmentOffset_iescriticalitydiagnostics+fragmentLength_iescriticalitydiagnostics] {
				if err := s05.BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s03.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("CriticalityDiagnostics")
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
	replayUsage := bb.Usage()

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
	opt_lppatransactionid, err := aper.DecodeBoolean(bb)
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
		val_procedurecode, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
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
	if opt_lppatransactionid {
		val_lppatransactionid, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "LppatransactionID")
		}
		tmp_lppatransactionid := s00.LPPATransactionID(val_lppatransactionid)
		if err := aper.ChargeValue(bb, tmp_lppatransactionid); err != nil {
			return err
		}
		v.LppatransactionID = (*s00.LPPATransactionID)(bb.OwnInt64(int64(tmp_lppatransactionid)))
	}
	if opt_iescriticalitydiagnostics {
		toleranceMark_iescriticalitydiagnostics := bb.EnterComponent("IEsCriticalityDiagnostics")
		tmp_iescriticalitydiagnostics := make(s05.CriticalityDiagnosticsIEList, 0)
		_, errCollection_iescriticalitydiagnostics := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_iescriticalitydiagnostics, fragmentLength_iescriticalitydiagnostics int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics < 0 || fragmentLength_iescriticalitydiagnostics > int64(^uint(0)>>1) || fragmentOffset_iescriticalitydiagnostics > int64(^uint(0)>>1)-fragmentLength_iescriticalitydiagnostics {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_iescriticalitydiagnostics; i++ {
				var elem s05.CriticalityDiagnosticsIEListElem
				elementMark := bb.EnterIndex(fragmentOffset_iescriticalitydiagnostics + i)
				if err := s05.BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		tmp_ieextensions := make(s03.CriticalityDiagnosticsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.CriticalityDiagnosticsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s03.BridgeCriticalityDiagnosticsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue struct {
	Value s05.CriticalityDiagnosticsIEList
}
type BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue struct {
	Value s06.InterRATMeasurementQuantities
}
type BridgeAsn1cAPERMeasurementQuantitiesListValue struct{ Value s06.MeasurementQuantities }
type BridgeAsn1cAPERMBSFNsubframeConfigurationListValue struct{ Value MBSFNsubframeConfiguration }

// MarshalAPER encodes MBSFNsubframeConfigurationValue to APER format.
func (v *MBSFNsubframeConfigurationValue) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := aper.EncodeEnumeratedAligned(bb, int64(v.RadioframeAllocationPeriod), 6, false); err != nil {
		return fmt.Errorf("encoding radioframeAllocationPeriod: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.RadioframeAllocationOffset), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7), false); err != nil {
		return fmt.Errorf("encoding radioframeAllocationOffset: %w", err)
	}
	if err := v.SubframeAllocation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding subframeAllocation: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes MBSFNsubframeConfigurationValue from APER format.
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNsubframeConfigurationValue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	bb.EnterComponent("MBSFNsubframeConfigurationValue")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	padding, err := aper.CaptureFinalBits(bb, "MBSFNsubframeConfigurationValue")
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfigurationValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MBSFNsubframeConfigurationValue) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNsubframeConfigurationValue{}
	val_radioframeallocationperiod, err := aper.DecodeEnumeratedAligned(bb, 6, false, aper.EnumerationSource{KnownExtensions: 0, Path: "RadioframeAllocationPeriod"})
	if err != nil {
		return runtime.WrapDecodePath(err, "RadioframeAllocationPeriod")
	}
	v.RadioframeAllocationPeriod = val_radioframeallocationperiod
	val_radioframeallocationoffset, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RadioframeAllocationOffset")
	}
	v.RadioframeAllocationOffset = val_radioframeallocationoffset
	toleranceMark_subframeallocation := bb.EnterComponent("SubframeAllocation")
	if err := v.SubframeAllocation.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SubframeAllocation")
	}
	bb.LeaveComponent(toleranceMark_subframeallocation)
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

type BridgeAsn1cAPERPosSIBSegmentsListValue struct{ Value s08.PosSIBSegments }
type BridgeAsn1cAPERSRSConfigurationForAllCellsListValue struct{ Value SRSConfigurationForAllCells }

// MarshalAPER encodes SRSConfigurationForOneCell to APER format.
func (v *SRSConfigurationForOneCell) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SRSConfigurationForOneCell) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MaxUpPts != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.DeltaSS != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Pci, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
		return fmt.Errorf("encoding pci: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.UlEarfcn, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
		return fmt.Errorf("encoding ul-earfcn: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.UlBandwidth), 6, false); err != nil {
		return fmt.Errorf("encoding ul-bandwidth: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.UlCyclicPrefixLength), 2, true); err != nil {
		return fmt.Errorf("encoding ul-cyclicPrefixLength: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidthConfig), 8, false); err != nil {
		return fmt.Errorf("encoding srs-BandwidthConfig: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SrsBandwidth), 4, false); err != nil {
		return fmt.Errorf("encoding srs-Bandwidth: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SrsAntennaPort), 3, true); err != nil {
		return fmt.Errorf("encoding srs-AntennaPort: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SrsHoppingBandwidth), 4, false); err != nil {
		return fmt.Errorf("encoding srs-HoppingBandwidth: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SrsCyclicShift), 8, false); err != nil {
		return fmt.Errorf("encoding srs-cyclicShift: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.SrsConfigIndex), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1023), false); err != nil {
		return fmt.Errorf("encoding srs-ConfigIndex: %w", err)
	}
	if v.MaxUpPts != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.MaxUpPts), 1, false); err != nil {
			return fmt.Errorf("encoding maxUpPts: %w", err)
		}
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.TransmissionComb), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1), false); err != nil {
		return fmt.Errorf("encoding transmissionComb: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.FreqDomainPosition), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(23), false); err != nil {
		return fmt.Errorf("encoding freqDomainPosition: %w", err)
	}
	if err := aper.EncodeBoolean(bb, v.GroupHoppingEnabled); err != nil {
		return fmt.Errorf("encoding groupHoppingEnabled: %w", err)
	}
	if v.DeltaSS != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.DeltaSS), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(29), false); err != nil {
			return fmt.Errorf("encoding deltaSS: %w", err)
		}
	}
	if err := aper.EncodeBitStringAligned(bb, v.SfnInitialisationTime.Bytes, v.SfnInitialisationTime.BitLength, 64, 64, true); err != nil {
		return fmt.Errorf("encoding sfnInitialisationTime: %w", err)
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

// UnmarshalAPER decodes SRSConfigurationForOneCell from APER format.
func (v *SRSConfigurationForOneCell) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SRSConfigurationForOneCell with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SRSConfigurationForOneCell) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	bb.EnterComponent("SRSConfigurationForOneCell")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	padding, err := aper.CaptureFinalBits(bb, "SRSConfigurationForOneCell")
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForOneCell")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SRSConfigurationForOneCell) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SRSConfigurationForOneCell{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_maxuppts, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_deltass, err := aper.DecodeBoolean(bb)
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
	val_ulbandwidth, err := aper.DecodeEnumeratedAligned(bb, 6, false, aper.EnumerationSource{KnownExtensions: 0, Path: "UlBandwidth"})
	if err != nil {
		return runtime.WrapDecodePath(err, "UlBandwidth")
	}
	v.UlBandwidth = val_ulbandwidth
	val_ulcyclicprefixlength, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UlCyclicPrefixLength"})
	if err != nil {
		return runtime.WrapDecodePath(err, "UlCyclicPrefixLength")
	}
	v.UlCyclicPrefixLength = s00.CPLength(val_ulcyclicprefixlength)
	val_srsbandwidthconfig, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "SrsBandwidthConfig"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsBandwidthConfig")
	}
	v.SrsBandwidthConfig = val_srsbandwidthconfig
	val_srsbandwidth, err := aper.DecodeEnumeratedAligned(bb, 4, false, aper.EnumerationSource{KnownExtensions: 0, Path: "SrsBandwidth"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsBandwidth")
	}
	v.SrsBandwidth = val_srsbandwidth
	val_srsantennaport, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SrsAntennaPort"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsAntennaPort")
	}
	v.SrsAntennaPort = val_srsantennaport
	val_srshoppingbandwidth, err := aper.DecodeEnumeratedAligned(bb, 4, false, aper.EnumerationSource{KnownExtensions: 0, Path: "SrsHoppingBandwidth"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsHoppingBandwidth")
	}
	v.SrsHoppingBandwidth = val_srshoppingbandwidth
	val_srscyclicshift, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "SrsCyclicShift"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsCyclicShift")
	}
	v.SrsCyclicShift = val_srscyclicshift
	val_srsconfigindex, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1023), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SrsConfigIndex")
	}
	v.SrsConfigIndex = val_srsconfigindex
	if opt_maxuppts {
		val_maxuppts, err := aper.DecodeEnumeratedAligned(bb, 1, false, aper.EnumerationSource{KnownExtensions: 0, Path: "MaxUpPts"})
		if err != nil {
			return runtime.WrapDecodePath(err, "MaxUpPts")
		}
		if err := aper.ChargeValue(bb, val_maxuppts); err != nil {
			return err
		}
		v.MaxUpPts = (*int64)(bb.OwnInt64(int64(val_maxuppts)))
	}
	val_transmissioncomb, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransmissionComb")
	}
	v.TransmissionComb = val_transmissioncomb
	val_freqdomainposition, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(23), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "FreqDomainPosition")
	}
	v.FreqDomainPosition = val_freqdomainposition
	val_grouphoppingenabled, err := aper.DecodeBoolean(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "GroupHoppingEnabled")
	}
	v.GroupHoppingEnabled = val_grouphoppingenabled
	if opt_deltass {
		val_deltass, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(29), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "DeltaSS")
		}
		if err := aper.ChargeValue(bb, val_deltass); err != nil {
			return err
		}
		v.DeltaSS = (*int64)(bb.OwnInt64(int64(val_deltass)))
	}
	bsBytes_sfninitialisationtime, bsBitLen_sfninitialisationtime, err := aper.DecodeBitStringAligned(bb, 64, 64, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "SfnInitialisationTime")
	}
	v.SfnInitialisationTime = runtime.BitString{Bytes: bsBytes_sfninitialisationtime, BitLength: bsBitLen_sfninitialisationtime}
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

// MarshalAPER encodes Subframeallocation to APER format.
func (v *Subframeallocation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Subframeallocation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("%s choice %d must be positive", "Subframeallocation:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.SubframeallocationChoiceOneFrame:
		if v.OneFrame == nil {
			return fmt.Errorf("choice alternative oneFrame is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.OneFrame.Bytes, v.OneFrame.BitLength, 6, 6, true); err != nil {
			return fmt.Errorf("encoding oneFrame: %w", err)
		}
	case s00.SubframeallocationChoiceFourFrames:
		if v.FourFrames == nil {
			return fmt.Errorf("choice alternative fourFrames is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.FourFrames.Bytes, v.FourFrames.BitLength, 24, 24, true); err != nil {
			return fmt.Errorf("encoding fourFrames: %w", err)
		}
	default:
		return fmt.Errorf("unknown Subframeallocation choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Subframeallocation from APER format.
func (v *Subframeallocation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Subframeallocation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Subframeallocation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Subframeallocation")
	}
	bb.EnterComponent("Subframeallocation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Subframeallocation")
	}
	padding, err := aper.CaptureFinalBits(bb, "Subframeallocation")
	if err != nil {
		return runtime.WrapDecodePath(err, "Subframeallocation")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Subframeallocation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Subframeallocation{}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.SubframeallocationChoiceOneFrame:
		bsBytes_oneframe, bsBitLen_oneframe, err := aper.DecodeBitStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "OneFrame")
		}
		tmp_oneframe := runtime.BitString{Bytes: bsBytes_oneframe, BitLength: bsBitLen_oneframe}
		if err := aper.ChargeValue(bb, tmp_oneframe); err != nil {
			return err
		}
		v.OneFrame = &tmp_oneframe
	case s00.SubframeallocationChoiceFourFrames:
		bsBytes_fourframes, bsBitLen_fourframes, err := aper.DecodeBitStringAligned(bb, 24, 24, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "FourFrames")
		}
		tmp_fourframes := runtime.BitString{Bytes: bsBytes_fourframes, BitLength: bsBitLen_fourframes}
		if err := aper.ChargeValue(bb, tmp_fourframes); err != nil {
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
func (v *CriticalityDiagnostics) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnostics", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnostics) WithoutReplay() CriticalityDiagnostics {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero CriticalityDiagnostics
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNsubframeConfigurationValue) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNsubframeConfigurationValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNsubframeConfigurationValue) WithoutReplay() MBSFNsubframeConfigurationValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MBSFNsubframeConfigurationValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SRSConfigurationForOneCell) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "SRSConfigurationForOneCell", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SRSConfigurationForOneCell) WithoutReplay() SRSConfigurationForOneCell {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero SRSConfigurationForOneCell
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Subframeallocation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "Subframeallocation", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Subframeallocation) WithoutReplay() Subframeallocation {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero Subframeallocation
	v.perPadding = zero.perPadding
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
func (v *SRSConfigurationForOneCell) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SRSConfigurationForOneCell) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SRSConfigurationForOneCell) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SRSConfigurationForOneCell.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *CriticalityDiagnostics) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnostics")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnostics")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnostics(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "CriticalityDiagnostics")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "CriticalityDiagnostics")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "CriticalityDiagnostics")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "CriticalityDiagnostics")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "CriticalityDiagnostics")
}
func (v *CriticalityDiagnostics) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnostics) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnostics) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *CriticalityDiagnostics) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnostics) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *MBSFNsubframeConfigurationValue) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MBSFNsubframeConfigurationValue")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *MBSFNsubframeConfigurationValue) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MBSFNsubframeConfigurationValue) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *SRSConfigurationForOneCell) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SRSConfigurationForOneCell")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "SRSConfigurationForOneCell")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSRSConfigurationForOneCell(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "SRSConfigurationForOneCell")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "SRSConfigurationForOneCell")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "SRSConfigurationForOneCell")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "SRSConfigurationForOneCell")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "SRSConfigurationForOneCell")
}
func (v *SRSConfigurationForOneCell) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SRSConfigurationForOneCell) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SRSConfigurationForOneCell) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *SRSConfigurationForOneCell) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SRSConfigurationForOneCell) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *Subframeallocation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Subframeallocation")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "Subframeallocation")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSubframeallocation(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "Subframeallocation")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "Subframeallocation")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "Subframeallocation")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "Subframeallocation")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "Subframeallocation")
}
func (v *Subframeallocation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *Subframeallocation) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *Subframeallocation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *Subframeallocation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *Subframeallocation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *CriticalityDiagnostics) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnostics")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnostics
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnostics(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnostics{}
		return report, aper.OperationError(err, "CriticalityDiagnostics")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnostics")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MBSFNsubframeConfigurationValue) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MBSFNsubframeConfigurationValue")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MBSFNsubframeConfigurationValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMBSFNsubframeConfigurationValue(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MBSFNsubframeConfigurationValue{}
		return report, aper.OperationError(err, "MBSFNsubframeConfigurationValue")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MBSFNsubframeConfigurationValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SRSConfigurationForOneCell) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SRSConfigurationForOneCell")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded SRSConfigurationForOneCell
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSRSConfigurationForOneCell(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SRSConfigurationForOneCell{}
		return report, aper.OperationError(err, "SRSConfigurationForOneCell")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SRSConfigurationForOneCell")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *Subframeallocation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Subframeallocation")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded Subframeallocation
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSubframeallocation(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = Subframeallocation{}
		return report, aper.OperationError(err, "Subframeallocation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Subframeallocation")
}

type BridgeAsn1cAPEROTDOAInformationTypeListValue struct{ Value s07.OTDOAInformationType }

func BridgeCaptureLPPaAssistanceInformationFailureList(v *s05.AssistanceInformationFailureList, s *aper.SemanticCapture) {
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
			s05.BridgeCaptureLPPaAssistanceInformationFailureListElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaAssistanceInformationFailureList(v *s05.AssistanceInformationFailureList, s *aper.SemanticComparison) {
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
			s05.BridgeCompareLPPaAssistanceInformationFailureListElem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaCriticalityDiagnostics(v *CriticalityDiagnostics, s *aper.SemanticCapture) {
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
			s00.BridgeCaptureLPPaProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			s00.BridgeCaptureLPPaTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			s00.BridgeCaptureLPPaCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.LppatransactionID == nil)
		if v.LppatransactionID != nil {
			s00.BridgeCaptureLPPaLPPATransactionID(v.LppatransactionID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeCriticalityDiagnosticsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnostics(v *CriticalityDiagnostics, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.Bool(v.ProcedureCode == nil)
		if v.ProcedureCode != nil {
			s02.BridgeCompareLPPaProcedureCode(v.ProcedureCode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.TriggeringMessage == nil)
		if v.TriggeringMessage != nil {
			s03.BridgeCompareLPPaTriggeringMessage(v.TriggeringMessage, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProcedureCriticality == nil)
		if v.ProcedureCriticality != nil {
			s02.BridgeCompareLPPaCriticality(v.ProcedureCriticality, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.LppatransactionID == nil)
		if v.LppatransactionID != nil {
			s02.BridgeCompareLPPaLPPATransactionID(v.LppatransactionID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEsCriticalityDiagnostics == nil)
	BridgeCompareLPPaCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeCriticalityDiagnosticsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEList(v *s05.CriticalityDiagnosticsIEList, s *aper.SemanticCapture) {
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
			s05.BridgeCaptureLPPaCriticalityDiagnosticsIEListElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEList(v *s05.CriticalityDiagnosticsIEList, s *aper.SemanticComparison) {
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
			s05.BridgeCompareLPPaCriticalityDiagnosticsIEListElem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaECIDMeasurementInitiationFailureIEValue(v *ECIDMeasurementInitiationFailureIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s00.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
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
					BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationFailureIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationFailureIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationFailureIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementInitiationFailureIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationFailureIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationFailureIEValue(v *ECIDMeasurementInitiationFailureIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s02.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
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
					BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationFailureIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationFailureIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationFailureIEValue) WithoutReplay() ECIDMeasurementInitiationFailureIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaMBSFNsubframeConfiguration(v *MBSFNsubframeConfiguration, s *aper.SemanticCapture) {
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
func BridgeCaptureLPPaMBSFNsubframeConfigurationValue(v *MBSFNsubframeConfigurationValue, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaMBSFNsubframeConfigurationValue(v *MBSFNsubframeConfigurationValue, s *aper.SemanticComparison) {
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
func BridgeCaptureLPPaPosSIBSegments(v *s08.PosSIBSegments, s *aper.SemanticCapture) {
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
			s08.BridgeCaptureLPPaPosSIBSegmentsElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaSRSConfigurationForAllCells(v *SRSConfigurationForAllCells, s *aper.SemanticCapture) {
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
func BridgeCaptureLPPaSRSConfigurationForOneCell(v *SRSConfigurationForOneCell, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPCI(&v.Pci, s)
	s00.BridgeCaptureLPPaEARFCN(&v.UlEarfcn, s)
	s.Int(int64(v.UlBandwidth))
	s00.BridgeCaptureLPPaCPLength(&v.UlCyclicPrefixLength, s)
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
	s00.BridgeCaptureLPPaSFNInitialisationTime(&v.SfnInitialisationTime, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForOneCell(v *SRSConfigurationForOneCell, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPCI(&v.Pci, s)
	s02.BridgeCompareLPPaEARFCN(&v.UlEarfcn, s)
	s.Int(int64(v.UlBandwidth))
	s02.BridgeCompareLPPaCPLength(&v.UlCyclicPrefixLength, s)
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
		s.End(f, aper.Snapshot{}, false)
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
		s.End(f, aper.Snapshot{}, false)
	}
	s03.BridgeCompareLPPaSFNInitialisationTime(&v.SfnInitialisationTime, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSubframeallocation(v *Subframeallocation, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SubframeallocationChoiceOneFrame:
		{
			f := s.Begin()
			s.Bool(v.OneFrame == nil)
			if v.OneFrame != nil {
				s.BitString((*v.OneFrame).Bytes, (*v.OneFrame).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.SubframeallocationChoiceFourFrames:
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
func BridgeCompareLPPaSubframeallocation(v *Subframeallocation, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.SubframeallocationChoiceOneFrame:
		{
			f := s.Begin()
			s.Bool(v.OneFrame == nil)
			if v.OneFrame != nil {
				s.BitString((*v.OneFrame).Bytes, (*v.OneFrame).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SubframeallocationChoiceFourFrames:
		{
			f := s.Begin()
			s.Bool(v.FourFrames == nil)
			if v.FourFrames != nil {
				s.BitString((*v.FourFrames).Bytes, (*v.FourFrames).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationRequestIEValue(v *UTDOAInformationRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedSRSTransmissionCharacteristics == nil)
				if v.rowRequestedSRSTransmissionCharacteristics != nil {
					s08.BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(v.rowRequestedSRSTransmissionCharacteristics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationRequestIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v UTDOAInformationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationRequestIEValue) captureSemantics(s aper.SemanticCapture) UTDOAInformationRequestIEValue {
	BridgeCaptureLPPaUTDOAInformationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationRequestIEValue(v *UTDOAInformationRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(12):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedSRSTransmissionCharacteristics == nil)
				if v.rowRequestedSRSTransmissionCharacteristics != nil {
					s08.BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v.rowRequestedSRSTransmissionCharacteristics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationRequestIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationRequestIEValue) WithoutReplay() UTDOAInformationRequestIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type ECIDMeasurementInitiationFailureIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowESMLCUEMeasurementID   *s00.MeasurementID
	rowCause                  *s05.Cause
	rowCriticalityDiagnostics *CriticalityDiagnostics
}

func (v ECIDMeasurementInitiationFailureIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case s00.ProtocolIEID(0):
		return v.rowCause != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementInitiationFailureIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationFailureIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationFailure-IEs"}}
}
func (ECIDMeasurementInitiationFailureIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
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

// AsESMLCUEMeasurementID returns the selected ESMLCUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationFailureIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsCause returns the selected Cause value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationFailureIEValue) AsCause() (*s05.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationFailureIEValue) AsCriticalityDiagnostics() (*CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ECIDMeasurementInitiationFailureIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementInitiationFailureIEValue, error) {
	out := ECIDMeasurementInitiationFailureIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 0, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true)
		value := s00.MeasurementID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
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
		var value CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
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
func (v ECIDMeasurementInitiationFailureIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationFailureIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-Cause:")
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationFailure-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementInitiationFailureIEValue:", v.id)
	}
}

type UTDOAInformationRequestIEValue struct {
	id                                         s00.ProtocolIEID
	withoutReplay                              bool
	received                                   aper.WireSpan
	replay                                     aper.Snapshot
	opaque                                     *aper.OpaqueOpenType
	isOpaque                                   bool
	rowRequestedSRSTransmissionCharacteristics *s08.RequestedSRSTransmissionCharacteristics
}

func (v UTDOAInformationRequestIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(12):
		return v.rowRequestedSRSTransmissionCharacteristics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *UTDOAInformationRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs"}}
}
func (UTDOAInformationRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(12):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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

// AsRequestedSRSTransmissionCharacteristics returns the selected RequestedSRSTransmissionCharacteristics value and reports whether that alternative is active.
func (v *UTDOAInformationRequestIEValue) AsRequestedSRSTransmissionCharacteristics() (*s08.RequestedSRSTransmissionCharacteristics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(12) || v.rowRequestedSRSTransmissionCharacteristics == nil {
		return nil, false
	}
	return v.rowRequestedSRSTransmissionCharacteristics, true
}
func (v UTDOAInformationRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UTDOAInformationRequestIEValue, error) {
	out := UTDOAInformationRequestIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 12:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(12):
		replayUsage := scope.Usage()
		var value s08.RequestedSRSTransmissionCharacteristics
		child := raw.ChildDecodeBuffer()
		if err := s08.BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestedSRSTransmissionCharacteristics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestedSRSTransmissionCharacteristics")
		if err != nil {
			return out, err
		}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsFieldPerPadding(&value) = padding
		*s08.BridgeRequestedSRSTransmissionCharacteristicsFieldReceived(&value) = true
		raw.RetainContents(s08.BridgeRequestedSRSTransmissionCharacteristicsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowRequestedSRSTransmissionCharacteristics = &value
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
func (v UTDOAInformationRequestIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(12):
		if v.rowRequestedSRSTransmissionCharacteristics == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationRequest-IEs.id-RequestedSRSTransmissionCharacteristics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s08.BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERBudget(v.rowRequestedSRSTransmissionCharacteristics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UTDOAInformationRequestIEValue:", v.id)
	}
}

type UTDOAInformationRequestIETable struct{}

func UTDOAInformationRequestIEs() UTDOAInformationRequestIETable {
	return UTDOAInformationRequestIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (UTDOAInformationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs"}
		return sealed
	}()
}
func (UTDOAInformationRequestIETable) infoRequestedSRSTransmissionCharacteristics() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationRequestIEs().ID(), ID: s00.ProtocolIEID(12), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "RequestedSRSTransmissionCharacteristics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationRequest-IEs", Row: "id-RequestedSRSTransmissionCharacteristics"}}}
}

// RequestedSRSTransmissionCharacteristics returns the typed binding for the RequestedSRSTransmissionCharacteristics row of this table.
func (t UTDOAInformationRequestIETable) RequestedSRSTransmissionCharacteristics() UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding {
	return UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding{info: t.infoRequestedSRSTransmissionCharacteristics(), codec: func() s08.RequestedSRSTransmissionCharacteristicsValueCodec {
		sealed := s08.RequestedSRSTransmissionCharacteristicsValueCodec{}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldPath(&sealed) = "RequestedSRSTransmissionCharacteristics"
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.RequestedSRSTransmissionCharacteristics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s08.RequestedSRSTransmissionCharacteristics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RequestedSRSTransmissionCharacteristics")
			var zero UTDOAInformationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(12), raw)
			if err != nil {
				var empty s08.RequestedSRSTransmissionCharacteristics
				return empty, runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
			}
			value, ok := decoded.AsRequestedSRSTransmissionCharacteristics()
			if !ok {
				var empty s08.RequestedSRSTransmissionCharacteristics
				return empty, fmt.Errorf("binding UTDOAInformationRequest-IEs.id-RequestedSRSTransmissionCharacteristics: no selected value")
			}
			return *value, nil
		}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(&sealed) = func(value s08.RequestedSRSTransmissionCharacteristics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationRequestIEValue{id: s00.ProtocolIEID(12), rowRequestedSRSTransmissionCharacteristics: &value}).encodeFresh(fresh, budget)
		}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCapture(&sealed) = func(v s08.RequestedSRSTransmissionCharacteristics, options aper.DecodeState) (s08.RequestedSRSTransmissionCharacteristics, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s08.BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()

			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCompare(&sealed) = func(v s08.RequestedSRSTransmissionCharacteristics, root aper.Snapshot, limits aper.ComparisonLimits,
		) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s08.BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(&v, &s)

			s.End(f, root, false)
			return s.Plan()
		}
		*s08.BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestedSRSTransmissionCharacteristics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s08.RequestedSRSTransmissionCharacteristics) UTDOAInformationRequestIEValue {
			return UTDOAInformationRequestIEValue{id: s00.ProtocolIEID(12), rowRequestedSRSTransmissionCharacteristics: &value}
		}, get: func(value *UTDOAInformationRequestIEValue) (*s08.RequestedSRSTransmissionCharacteristics, bool) {
			return value.AsRequestedSRSTransmissionCharacteristics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t UTDOAInformationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UTDOAInformationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(12):
		return UTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RequestedSRSTransmissionCharacteristics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return UTDOAInformationRequestIEField{Id: id, Criticality: criticality, Value: UTDOAInformationRequestIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// MBSFNsubframeConfigurationValueCodec binds the complete source value type.
func MBSFNsubframeConfigurationValueCodec() MBSFNsubframeConfigurationValueValueCodec {
	return MBSFNsubframeConfigurationValueValueCodec{path: "MBSFNsubframeConfigurationValue", decode: func(data []byte, options aper.DecodeState) (MBSFNsubframeConfigurationValue, error) {
		var value MBSFNsubframeConfigurationValue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MBSFNsubframeConfigurationValue{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MBSFNsubframeConfigurationValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MBSFNsubframeConfigurationValue, options aper.DecodeState) (MBSFNsubframeConfigurationValue, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaMBSFNsubframeConfigurationValue(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MBSFNsubframeConfigurationValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaMBSFNsubframeConfigurationValue(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNsubframeConfigurationValue"
		return sealed
	}(),
	}
}

// RequestedSRSTransmissionCharacteristicsCodec binds the complete APER value type.
func RequestedSRSTransmissionCharacteristicsCodec() s08.RequestedSRSTransmissionCharacteristicsValueCodec {
	return UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Codec()
}

// SRSConfigurationForOneCellCodec binds the complete source value type.
func SRSConfigurationForOneCellCodec() SRSConfigurationForOneCellValueCodec {
	return SRSConfigurationForOneCellValueCodec{path: "SRSConfigurationForOneCell", decode: func(data []byte, options aper.DecodeState) (SRSConfigurationForOneCell, error) {
		var value SRSConfigurationForOneCell
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SRSConfigurationForOneCell{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SRSConfigurationForOneCell, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SRSConfigurationForOneCell, options aper.DecodeState) (SRSConfigurationForOneCell, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSRSConfigurationForOneCell(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SRSConfigurationForOneCell, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSRSConfigurationForOneCell(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRSConfigurationForOneCell"
		return sealed
	}(),
	}
}

// SubframeallocationCodec binds the complete source value type.
func SubframeallocationCodec() SubframeallocationValueCodec {
	return SubframeallocationValueCodec{path: "Subframeallocation", decode: func(data []byte, options aper.DecodeState) (Subframeallocation, error) {
		var value Subframeallocation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return Subframeallocation{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value Subframeallocation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v Subframeallocation, options aper.DecodeState) (Subframeallocation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSubframeallocation(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f,
			&root,
			false)
		return v, root
	}, compare: func(v Subframeallocation, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSubframeallocation(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Subframeallocation"
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
func (r *ValidationReport) addDeferred(item s00.DeferredCondition) {
	if err := r.reserveReport(item.Location); err != nil {
		return
	}
	r.Deferred = append(r.Deferred, item)
}
func (r *ValidationReport) addUnchecked(location aper.Location) {
	if err := r.reserveReport(location); err != nil {
		return
	}
	r.Unchecked = append(r.Unchecked, location)
}
func (r *ValidationReport) reserveReport(location aper.Location) error {
	if r.err != nil {
		return r.err
	}
	if r.budget == nil {
		return nil
	}
	bb := aper.NewBudgetBuffer(r.budget)
	if err := bb.ChargeLocatedReport(location, 1024); err != nil {
		r.err = err
		return err
	}
	return nil
}

type ValidationIssue struct {
	Code                s00.ValidationCode
	Severity            s00.ValidationSeverity
	Location            aper.Location
	Table               s00.TableID
	IEID                s00.ProtocolIEID
	HasIEID             bool
	PrivateID           *s08.PrivateIEID
	ExpectedCriticality *s00.Criticality
	ReceivedCriticality *s00.Criticality
	Rule                aper.SourceRule
	RelatedRules        []aper.SourceRule
}
type ValidationReport struct {
	budget    *aper.DecodeBudget
	err       error
	Issues    []ValidationIssue
	Deferred  []s00.DeferredCondition
	Unchecked []aper.Location
	Complete  bool
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ECIDMeasurementInitiationFailureIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if v.rowESMLCUEMeasurementID != nil {
			return v.rowESMLCUEMeasurementID, true
		}
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
func (v *UTDOAInformationRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 12:
		if v.rowRequestedSRSTransmissionCharacteristics != nil {
			return v.rowRequestedSRSTransmissionCharacteristics, true
		}
	}
	return nil, false
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
func BridgeCriticalityDiagnosticsFieldReceivedBytes(v *CriticalityDiagnostics) *aper.WireSpan {
	return &v.receivedBytes
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
func BridgeCriticalityDiagnosticsMethodMarshalAPERChanged(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERChangedValue(v *CriticalityDiagnostics, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERFreshValue(v *CriticalityDiagnostics, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERLegacy(v *CriticalityDiagnostics) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsMethodMarshalAPERPlanned(v *CriticalityDiagnostics, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
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
func BridgeCriticalityDiagnosticsValueCodecFieldCompare(v *CriticalityDiagnosticsValueCodec) *func(CriticalityDiagnostics, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeBudget(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsValueCodecMethodEncodeChanged(v CriticalityDiagnosticsValueCodec, a0 CriticalityDiagnostics, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureCauseIEBinding) *s05.CauseValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldGet(v *ECIDMeasurementInitiationFailureCauseIEBinding) *func(*ECIDMeasurementInitiationFailureIEValue) (*s05.Cause, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureCauseIEBindingFieldInject(v *ECIDMeasurementInitiationFailureCauseIEBinding) *func(s05.Cause) ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldCodec(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldGet(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *func(*ECIDMeasurementInitiationFailureIEValue) (*CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInfo(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBindingFieldInject(v *ECIDMeasurementInitiationFailureCriticalityDiagnosticsIEBinding) *func(CriticalityDiagnostics) ECIDMeasurementInitiationFailureIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldReceived(v *ECIDMeasurementInitiationFailureIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v *ECIDMeasurementInitiationFailureIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldStream(v *ECIDMeasurementInitiationFailureIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationFailureIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationFailureIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationFailureIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationFailureIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldId(v *ECIDMeasurementInitiationFailureIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldIsOpaque(v *ECIDMeasurementInitiationFailureIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldOpaque(v *ECIDMeasurementInitiationFailureIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldReceived(v *ECIDMeasurementInitiationFailureIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldReplay(v *ECIDMeasurementInitiationFailureIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowCause(v *ECIDMeasurementInitiationFailureIEValue) **s05.Cause {
	return &v.rowCause
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowCriticalityDiagnostics(v *ECIDMeasurementInitiationFailureIEValue) **CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationFailureIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationFailureIEValueFieldWithoutReplay(v *ECIDMeasurementInitiationFailureIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureFraming(v ECIDMeasurementInitiationFailureIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationFailureIEValue, a0 aper.SemanticCapture) ECIDMeasurementInitiationFailureIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationFailureIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodCompareSemantics(v ECIDMeasurementInitiationFailureIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodDecode(v ECIDMeasurementInitiationFailureIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementInitiationFailureIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodEncode(v ECIDMeasurementInitiationFailureIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodEncodeFresh(v ECIDMeasurementInitiationFailureIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodMatchesID(v ECIDMeasurementInitiationFailureIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodReason(v ECIDMeasurementInitiationFailureIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationFailureIEValueMethodRule(v ECIDMeasurementInitiationFailureIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldContext(v *MBSFNsubframeConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldReceived(v *MBSFNsubframeConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldReplay(v *MBSFNsubframeConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationAPERValueFieldWithoutReplay(v *MBSFNsubframeConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCapture(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, aper.DecodeState) (MBSFNsubframeConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCompare(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldContext(v *MBSFNsubframeConfigurationConcreteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldDecode(v *MBSFNsubframeConfigurationConcreteValueCodec) *func([]byte, aper.DecodeState) (MBSFNsubframeConfiguration, error) {
	return &v.decode
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldEncode(v *MBSFNsubframeConfigurationConcreteValueCodec) *func(MBSFNsubframeConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldPath(v *MBSFNsubframeConfigurationConcreteValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecMethodEncodeBudget(v MBSFNsubframeConfigurationConcreteValueCodec, a0 MBSFNsubframeConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationConcreteValueCodecMethodEncodeChanged(v MBSFNsubframeConfigurationConcreteValueCodec, a0 MBSFNsubframeConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldContext(v *MBSFNsubframeConfigurationValueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldReceived(v *MBSFNsubframeConfigurationValueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldReplay(v *MBSFNsubframeConfigurationValueAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationValueAPERValueFieldWithoutReplay(v *MBSFNsubframeConfigurationValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationValueFieldPerPadding(v *MBSFNsubframeConfigurationValue) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMBSFNsubframeConfigurationValueFieldReceived(v *MBSFNsubframeConfigurationValue) *bool {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationValueFieldReceivedBytes(v *MBSFNsubframeConfigurationValue) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNsubframeConfigurationValueFieldReplay(v *MBSFNsubframeConfigurationValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationValueFieldStream(v *MBSFNsubframeConfigurationValue) *aper.WireSpan {
	return &v.stream
}
func BridgeMBSFNsubframeConfigurationValueFieldWithoutReplay(v *MBSFNsubframeConfigurationValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERBudget(v *MBSFNsubframeConfigurationValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERChanged(v *MBSFNsubframeConfigurationValue, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERChangedValue(v *MBSFNsubframeConfigurationValue, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERFreshValue(v *MBSFNsubframeConfigurationValue, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERLegacy(v *MBSFNsubframeConfigurationValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERPlanned(v *MBSFNsubframeConfigurationValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(v *MBSFNsubframeConfigurationValue, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(v *MBSFNsubframeConfigurationValue, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERLegacy(v *MBSFNsubframeConfigurationValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERWithOptions(v *MBSFNsubframeConfigurationValue, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldCapture(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, aper.DecodeState) (MBSFNsubframeConfigurationValue, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldCompare(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldContext(v *MBSFNsubframeConfigurationValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldDecode(v *MBSFNsubframeConfigurationValueValueCodec) *func([]byte, aper.DecodeState) (MBSFNsubframeConfigurationValue, error) {
	return &v.decode
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldEncode(v *MBSFNsubframeConfigurationValueValueCodec) *func(MBSFNsubframeConfigurationValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNsubframeConfigurationValueValueCodecFieldPath(v *MBSFNsubframeConfigurationValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNsubframeConfigurationValueValueCodecMethodEncodeBudget(v MBSFNsubframeConfigurationValueValueCodec, a0 MBSFNsubframeConfigurationValue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationValueValueCodecMethodEncodeChanged(v MBSFNsubframeConfigurationValueValueCodec, a0 MBSFNsubframeConfigurationValue, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldContext(v *SRSConfigurationForAllCellsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldReceived(v *SRSConfigurationForAllCellsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldReplay(v *SRSConfigurationForAllCellsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForAllCellsAPERValueFieldWithoutReplay(v *SRSConfigurationForAllCellsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldCapture(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, aper.DecodeState) (SRSConfigurationForAllCells, aper.Snapshot) {
	return &v.capture
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldCompare(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldContext(v *SRSConfigurationForAllCellsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldDecode(v *SRSConfigurationForAllCellsValueCodec) *func([]byte, aper.DecodeState) (SRSConfigurationForAllCells, error) {
	return &v.decode
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldEncode(v *SRSConfigurationForAllCellsValueCodec) *func(SRSConfigurationForAllCells, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRSConfigurationForAllCellsValueCodecFieldPath(v *SRSConfigurationForAllCellsValueCodec) *aper.Path {
	return &v.path
}
func BridgeSRSConfigurationForAllCellsValueCodecMethodEncodeBudget(v SRSConfigurationForAllCellsValueCodec, a0 SRSConfigurationForAllCells, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsValueCodecMethodEncodeChanged(v SRSConfigurationForAllCellsValueCodec, a0 SRSConfigurationForAllCells, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSRSConfigurationForOneCellAPERValueFieldContext(v *SRSConfigurationForOneCellAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForOneCellAPERValueFieldReceived(v *SRSConfigurationForOneCellAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSRSConfigurationForOneCellAPERValueFieldReplay(v *SRSConfigurationForOneCellAPERValue) *aper.Snapshot {
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
func BridgeSRSConfigurationForOneCellFieldExtOrigin(v *SRSConfigurationForOneCell) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSRSConfigurationForOneCellFieldExtPresent(v *SRSConfigurationForOneCell) *[]bool {
	return &v.extPresent
}
func BridgeSRSConfigurationForOneCellFieldExtWire(v *SRSConfigurationForOneCell) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSRSConfigurationForOneCellFieldGroupHoppingEnabledRaw(v *SRSConfigurationForOneCell) *byte {
	return &v.groupHoppingEnabledRaw
}
func BridgeSRSConfigurationForOneCellFieldPerExtPadding(v *SRSConfigurationForOneCell) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSRSConfigurationForOneCellFieldPerPadding(v *SRSConfigurationForOneCell) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSRSConfigurationForOneCellFieldReceived(v *SRSConfigurationForOneCell) *bool {
	return &v.received
}
func BridgeSRSConfigurationForOneCellFieldReceivedBytes(v *SRSConfigurationForOneCell) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSRSConfigurationForOneCellFieldReplay(v *SRSConfigurationForOneCell) *aper.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForOneCellFieldStream(v *SRSConfigurationForOneCell) *aper.WireSpan {
	return &v.stream
}
func BridgeSRSConfigurationForOneCellFieldWithoutReplay(v *SRSConfigurationForOneCell) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERBudget(v *SRSConfigurationForOneCell, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERChanged(v *SRSConfigurationForOneCell, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERChangedValue(v *SRSConfigurationForOneCell, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERFreshValue(v *SRSConfigurationForOneCell, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERLegacy(v *SRSConfigurationForOneCell) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERPlanned(v *SRSConfigurationForOneCell, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(v *SRSConfigurationForOneCell, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(v *SRSConfigurationForOneCell, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERLegacy(v *SRSConfigurationForOneCell, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSRSConfigurationForOneCellMethodUnmarshalAPERWithOptions(v *SRSConfigurationForOneCell, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSRSConfigurationForOneCellValueCodecFieldCapture(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, aper.DecodeState) (SRSConfigurationForOneCell, aper.Snapshot) {
	return &v.capture
}
func BridgeSRSConfigurationForOneCellValueCodecFieldCompare(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSRSConfigurationForOneCellValueCodecFieldContext(v *SRSConfigurationForOneCellValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRSConfigurationForOneCellValueCodecFieldDecode(v *SRSConfigurationForOneCellValueCodec) *func([]byte, aper.DecodeState) (SRSConfigurationForOneCell, error) {
	return &v.decode
}
func BridgeSRSConfigurationForOneCellValueCodecFieldEncode(v *SRSConfigurationForOneCellValueCodec) *func(SRSConfigurationForOneCell, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRSConfigurationForOneCellValueCodecFieldPath(v *SRSConfigurationForOneCellValueCodec) *aper.Path {
	return &v.path
}
func BridgeSRSConfigurationForOneCellValueCodecMethodEncodeBudget(v SRSConfigurationForOneCellValueCodec, a0 SRSConfigurationForOneCell, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSRSConfigurationForOneCellValueCodecMethodEncodeChanged(v SRSConfigurationForOneCellValueCodec, a0 SRSConfigurationForOneCell, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSubframeallocationAPERValueFieldContext(v *SubframeallocationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubframeallocationAPERValueFieldReceived(v *SubframeallocationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSubframeallocationAPERValueFieldReplay(v *SubframeallocationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSubframeallocationAPERValueFieldWithoutReplay(v *SubframeallocationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSubframeallocationFieldPerOpenTypePadding(v *Subframeallocation) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSubframeallocationFieldPerPadding(v *Subframeallocation) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSubframeallocationFieldReceived(v *Subframeallocation) *bool { return &v.received }
func BridgeSubframeallocationFieldReceivedBytes(v *Subframeallocation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSubframeallocationFieldReplay(v *Subframeallocation) *aper.Snapshot { return &v.replay }
func BridgeSubframeallocationFieldStream(v *Subframeallocation) *aper.WireSpan { return &v.stream }
func BridgeSubframeallocationFieldWithoutReplay(v *Subframeallocation) *bool   { return &v.withoutReplay }
func BridgeSubframeallocationMethodMarshalAPERBudget(v *Subframeallocation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERChanged(v *Subframeallocation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSubframeallocationMethodMarshalAPERChangedValue(v *Subframeallocation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSubframeallocationMethodMarshalAPERFreshValue(v *Subframeallocation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERLegacy(v *Subframeallocation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSubframeallocationMethodMarshalAPERPlanned(v *Subframeallocation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSubframeallocationMethodMarshalAPERTo(v *Subframeallocation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSubframeallocationMethodUnmarshalAPERFrom(v *Subframeallocation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSubframeallocationMethodUnmarshalAPERLegacy(v *Subframeallocation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSubframeallocationMethodUnmarshalAPERWithOptions(v *Subframeallocation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSubframeallocationValueCodecFieldCapture(v *SubframeallocationValueCodec) *func(Subframeallocation, aper.DecodeState) (Subframeallocation, aper.Snapshot) {
	return &v.capture
}
func BridgeSubframeallocationValueCodecFieldCompare(v *SubframeallocationValueCodec) *func(Subframeallocation, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSubframeallocationValueCodecFieldContext(v *SubframeallocationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubframeallocationValueCodecFieldDecode(v *SubframeallocationValueCodec) *func([]byte, aper.DecodeState) (Subframeallocation, error) {
	return &v.decode
}
func BridgeSubframeallocationValueCodecFieldEncode(v *SubframeallocationValueCodec) *func(Subframeallocation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubframeallocationValueCodecFieldPath(v *SubframeallocationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSubframeallocationValueCodecMethodEncodeBudget(v SubframeallocationValueCodec, a0 Subframeallocation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSubframeallocationValueCodecMethodEncodeChanged(v SubframeallocationValueCodec, a0 Subframeallocation, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationRequestIEFieldFieldReceived(v *UTDOAInformationRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationRequestIEFieldFieldReplay(v *UTDOAInformationRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestIEFieldFieldStream(v *UTDOAInformationRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationRequestIEFieldFieldWithoutReplay(v *UTDOAInformationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestIEFieldMethodMarshalAPERTo(v *UTDOAInformationRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationRequestIETableMethodInfoRequestedSRSTransmissionCharacteristics(v UTDOAInformationRequestIETable) s00.FieldInfo {
	return v.infoRequestedSRSTransmissionCharacteristics()
}
func BridgeUTDOAInformationRequestIEValueFieldId(v *UTDOAInformationRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationRequestIEValueFieldIsOpaque(v *UTDOAInformationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationRequestIEValueFieldOpaque(v *UTDOAInformationRequestIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationRequestIEValueFieldReceived(v *UTDOAInformationRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationRequestIEValueFieldReplay(v *UTDOAInformationRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationRequestIEValueFieldRowRequestedSRSTransmissionCharacteristics(v *UTDOAInformationRequestIEValue) **s08.RequestedSRSTransmissionCharacteristics {
	return &v.rowRequestedSRSTransmissionCharacteristics
}
func BridgeUTDOAInformationRequestIEValueFieldWithoutReplay(v *UTDOAInformationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureFraming(v UTDOAInformationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureSemantics(v UTDOAInformationRequestIEValue, a0 aper.SemanticCapture) UTDOAInformationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodCaptureSnapshot(v UTDOAInformationRequestIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationRequestIEValueMethodCompareSemantics(v UTDOAInformationRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodDecode(v UTDOAInformationRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UTDOAInformationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodEncode(v UTDOAInformationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationRequestIEValueMethodEncodeFresh(v UTDOAInformationRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodMatchesID(v UTDOAInformationRequestIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationRequestIEValueMethodReason(v UTDOAInformationRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationRequestIEValueMethodRule(v UTDOAInformationRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldCodec(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *s08.RequestedSRSTransmissionCharacteristicsValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldGet(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *func(*UTDOAInformationRequestIEValue) (*s08.RequestedSRSTransmissionCharacteristics, bool) {
	return &v.get
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldInfo(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBindingFieldInject(v *UTDOAInformationRequestRequestedSRSTransmissionCharacteristicsIEBinding) *func(s08.RequestedSRSTransmissionCharacteristics) UTDOAInformationRequestIEValue {
	return &v.inject
}
func BridgeValidationReportFieldBudget(v *ValidationReport) **aper.DecodeBudget { return &v.budget }
func BridgeValidationReportFieldErr(v *ValidationReport) *error                 { return &v.err }
func BridgeValidationReportMethodAddDeferred(v *ValidationReport, a0 s00.DeferredCondition) {
	v.addDeferred(a0)
}
func BridgeValidationReportMethodAddIssue(v *ValidationReport, a0 ValidationIssue) { v.addIssue(a0) }
func BridgeValidationReportMethodAddUnchecked(v *ValidationReport, a0 aper.Location) {
	v.addUnchecked(a0)
}
func BridgeValidationReportMethodReserveReport(v *ValidationReport, a0 aper.Location) error {
	return v.reserveReport(a0)
}
