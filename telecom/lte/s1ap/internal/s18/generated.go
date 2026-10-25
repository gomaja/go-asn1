// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s18 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s18

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// HandoverCancelIEContainer is the concrete ProtocolIEContainer[HandoverCancelIEValue].
type HandoverCancelIEContainer []HandoverCancelIEField

// HandoverCancelIEField is the concrete ProtocolIEField[HandoverCancelIEValue].
type HandoverCancelIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverCancelIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEField) WithoutReplay() HandoverCancelIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverCancelIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverCancelIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverCancelIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverCancelIEField{}
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
	var zero HandoverCancelIEValue

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

// LocationReportingFailureIndicationIEContainer is the concrete ProtocolIEContainer[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEContainer []LocationReportingFailureIndicationIEField

// LocationReportingFailureIndicationIEField is the concrete ProtocolIEField[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         LocationReportingFailureIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEField) WithoutReplay() LocationReportingFailureIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *LocationReportingFailureIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *LocationReportingFailureIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *LocationReportingFailureIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReportingFailureIndicationIEField{}
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
	var zero LocationReportingFailureIndicationIEValue

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

// LTENTNTAIInformationValueCodec is the concrete ValueCodec[LTENTNTAIInformation].
type LTENTNTAIInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LTENTNTAIInformation,

		error)
	encode func(LTENTNTAIInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LTENTNTAIInformation, aper.DecodeState,

	) (LTENTNTAIInformation, aper.Snapshot,

	)
	compare func(LTENTNTAIInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LTENTNTAIInformationValueCodec) New(value LTENTNTAIInformation,

) (LTENTNTAIInformationAPERValue, error) {
	if c.encode == nil {
		return LTENTNTAIInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LTENTNTAIInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LTENTNTAIInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LTENTNTAIInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LTENTNTAIInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LTENTNTAIInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LTENTNTAIInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LTENTNTAIInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LTENTNTAIInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LTENTNTAIInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LTENTNTAIInformationValueCodec) EncodeAPER(value LTENTNTAIInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LTENTNTAIInformationValueCodec) encodeBudgetValue(value LTENTNTAIInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LTENTNTAIInformationValueCodec) encodeChanged(value LTENTNTAIInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABLevelQoSParametersValueCodec is the concrete ValueCodec[ERABLevelQoSParameters].
type ERABLevelQoSParametersValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABLevelQoSParameters,

		error)
	encode func(ERABLevelQoSParameters,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABLevelQoSParameters, aper.DecodeState,

	) (ERABLevelQoSParameters, aper.Snapshot,

	)
	compare func(ERABLevelQoSParameters, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABLevelQoSParametersValueCodec) New(value ERABLevelQoSParameters,

) (ERABLevelQoSParametersAPERValue, error) {
	if c.encode == nil {
		return ERABLevelQoSParametersAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABLevelQoSParametersAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABLevelQoSParametersAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABLevelQoSParametersAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABLevelQoSParametersValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABLevelQoSParametersAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABLevelQoSParametersAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABLevelQoSParametersAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABLevelQoSParametersAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABLevelQoSParametersAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABLevelQoSParametersValueCodec) EncodeAPER(value ERABLevelQoSParametersAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABLevelQoSParametersValueCodec) encodeBudgetValue(value ERABLevelQoSParameters,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABLevelQoSParametersValueCodec) encodeChanged(value ERABLevelQoSParameters,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverCancelIEValue].
type HandoverCancelMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverCancelIEValue

	get func(*HandoverCancelIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCancelMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverCancelIEField, error) {
	if b.inject == nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelMMEUES1APIDIEBinding) Get(field *HandoverCancelIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCancelENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverCancelIEValue].
type HandoverCancelENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverCancelIEValue

	get func(*HandoverCancelIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCancelENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverCancelIEField, error) {
	if b.inject == nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelENBUES1APIDIEBinding) Get(field *HandoverCancelIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverCancelCauseIEBinding is the concrete IEBinding[Cause, HandoverCancelIEValue].
type HandoverCancelCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) HandoverCancelIEValue

	get func(*HandoverCancelIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverCancelCauseIEBinding) New(value s14.Cause,

) (HandoverCancelIEField, error) {
	if b.inject == nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverCancelIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverCancelIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverCancelCauseIEBinding) Get(field *HandoverCancelIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// GUMMEIValueCodec is the concrete ValueCodec[GUMMEI].
type GUMMEIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GUMMEI,

		error)
	encode func(GUMMEI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GUMMEI, aper.DecodeState,

	) (GUMMEI, aper.Snapshot,

	)
	compare func(GUMMEI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GUMMEIValueCodec) New(value GUMMEI,

) (GUMMEIAPERValue, error) {
	if c.encode == nil {
		return GUMMEIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GUMMEIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GUMMEIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GUMMEIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GUMMEIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GUMMEIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GUMMEIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GUMMEIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GUMMEIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GUMMEIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GUMMEIValueCodec) EncodeAPER(value GUMMEIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GUMMEIValueCodec) encodeBudgetValue(value GUMMEI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GUMMEIValueCodec) encodeChanged(value GUMMEI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEBehaviourValueCodec is the concrete ValueCodec[ExpectedUEBehaviour].
type ExpectedUEBehaviourValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEBehaviour,

		error)
	encode func(ExpectedUEBehaviour,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEBehaviour, aper.DecodeState,

	) (ExpectedUEBehaviour, aper.Snapshot,

	)
	compare func(ExpectedUEBehaviour, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEBehaviourValueCodec) New(value ExpectedUEBehaviour,

) (ExpectedUEBehaviourAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEBehaviourAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEBehaviourAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEBehaviourAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEBehaviourAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEBehaviourValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEBehaviourAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEBehaviourAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEBehaviourAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEBehaviourAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEBehaviourAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEBehaviourValueCodec) EncodeAPER(value ExpectedUEBehaviourAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEBehaviourValueCodec) encodeBudgetValue(value ExpectedUEBehaviour,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEBehaviourValueCodec) encodeChanged(value ExpectedUEBehaviour,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LAIValueCodec is the concrete ValueCodec[LAI].
type LAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LAI,

		error)
	encode func(LAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LAI, aper.DecodeState,

	) (LAI, aper.Snapshot,

	)
	compare func(LAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LAIValueCodec) New(value LAI,

) (LAIAPERValue, error) {
	if c.encode == nil {
		return LAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LAIValueCodec) EncodeAPER(value LAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LAIValueCodec) encodeBudgetValue(value LAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LAIValueCodec) encodeChanged(value LAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) LocationReportingFailureIndicationIEValue

	get func(*LocationReportingFailureIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingFailureIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingFailureIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingFailureIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (LocationReportingFailureIndicationIEField, error) {
	if b.inject == nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingFailureIndicationENBUES1APIDIEBinding) Get(field *LocationReportingFailureIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportingFailureIndicationCauseIEBinding is the concrete IEBinding[Cause, LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) LocationReportingFailureIndicationIEValue

	get func(*LocationReportingFailureIndicationIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Codec() s14.CauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingFailureIndicationCauseIEBinding) New(value s14.Cause,

) (LocationReportingFailureIndicationIEField, error) {
	if b.inject == nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Get(field *LocationReportingFailureIndicationIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// GUMMEIListValueCodec is the concrete ValueCodec[GUMMEIList].
type GUMMEIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GUMMEIList,

		error)
	encode func(GUMMEIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GUMMEIList, aper.DecodeState,

	) (GUMMEIList, aper.Snapshot,

	)
	compare func(GUMMEIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GUMMEIListValueCodec) New(value GUMMEIList,

) (GUMMEIListAPERValue, error) {
	if c.encode == nil {
		return GUMMEIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GUMMEIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GUMMEIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GUMMEIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GUMMEIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GUMMEIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GUMMEIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GUMMEIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GUMMEIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GUMMEIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GUMMEIListValueCodec) EncodeAPER(value GUMMEIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GUMMEIListValueCodec) encodeBudgetValue(value GUMMEIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GUMMEIListValueCodec) encodeChanged(value GUMMEIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalENBIDValueCodec is the concrete ValueCodec[GlobalENBID].
type GlobalENBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalENBID,

		error)
	encode func(GlobalENBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalENBID, aper.DecodeState,

	) (GlobalENBID, aper.Snapshot,

	)
	compare func(GlobalENBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalENBIDValueCodec) New(value GlobalENBID,

) (GlobalENBIDAPERValue, error) {
	if c.encode == nil {
		return GlobalENBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalENBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalENBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalENBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalENBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalENBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalENBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalENBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalENBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalENBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalENBIDValueCodec) EncodeAPER(value GlobalENBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GlobalENBIDValueCodec) encodeBudgetValue(value GlobalENBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalENBIDValueCodec) encodeChanged(value GlobalENBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AdditionalGUTIValueCodec is the concrete ValueCodec[AdditionalGUTI].
type AdditionalGUTIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AdditionalGUTI,

		error)
	encode func(AdditionalGUTI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AdditionalGUTI, aper.DecodeState,

	) (AdditionalGUTI, aper.Snapshot,

	)
	compare func(AdditionalGUTI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AdditionalGUTIValueCodec) New(value AdditionalGUTI,

) (AdditionalGUTIAPERValue, error) {
	if c.encode == nil {
		return AdditionalGUTIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AdditionalGUTIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AdditionalGUTIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AdditionalGUTIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AdditionalGUTIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AdditionalGUTIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AdditionalGUTIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AdditionalGUTIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AdditionalGUTIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AdditionalGUTIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AdditionalGUTIValueCodec) EncodeAPER(value AdditionalGUTIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AdditionalGUTIValueCodec) encodeBudgetValue(value AdditionalGUTI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AdditionalGUTIValueCodec) encodeChanged(value AdditionalGUTI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CandidateCellListValueCodec is the concrete ValueCodec[CandidateCellList].
type CandidateCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CandidateCellList,

		error)
	encode func(CandidateCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CandidateCellList, aper.DecodeState,

	) (CandidateCellList, aper.Snapshot,

	)
	compare func(CandidateCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CandidateCellListValueCodec) New(value CandidateCellList,

) (CandidateCellListAPERValue, error) {
	if c.encode == nil {
		return CandidateCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CandidateCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CandidateCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CandidateCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CandidateCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CandidateCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CandidateCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CandidateCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CandidateCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CandidateCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CandidateCellListValueCodec) EncodeAPER(value CandidateCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CandidateCellListValueCodec) encodeBudgetValue(value CandidateCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CandidateCellListValueCodec) encodeChanged(value CandidateCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EUTRANcellLoadReportingResponseValueCodec is the concrete ValueCodec[EUTRANcellLoadReportingResponse].
type EUTRANcellLoadReportingResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s17.EUTRANcellLoadReportingResponse,

		error)
	encode func(s17.EUTRANcellLoadReportingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s17.EUTRANcellLoadReportingResponse, aper.DecodeState,

	) (s17.EUTRANcellLoadReportingResponse, aper.Snapshot,

	)
	compare func(s17.EUTRANcellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EUTRANcellLoadReportingResponseValueCodec) New(value s17.EUTRANcellLoadReportingResponse,

) (EUTRANcellLoadReportingResponseAPERValue, error) {
	if c.encode == nil {
		return EUTRANcellLoadReportingResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANcellLoadReportingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANcellLoadReportingResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EUTRANcellLoadReportingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EUTRANcellLoadReportingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANcellLoadReportingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EUTRANcellLoadReportingResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EUTRANcellLoadReportingResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EUTRANcellLoadReportingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EUTRANcellLoadReportingResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EUTRANcellLoadReportingResponseValueCodec) EncodeAPER(value EUTRANcellLoadReportingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EUTRANcellLoadReportingResponseValueCodec) encodeBudgetValue(value s17.EUTRANcellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EUTRANcellLoadReportingResponseValueCodec) encodeChanged(value s17.EUTRANcellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggeredCellLoadReportingRequestValueCodec is the concrete ValueCodec[EventTriggeredCellLoadReportingRequest].
type EventTriggeredCellLoadReportingRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggeredCellLoadReportingRequest,

		error)
	encode func(EventTriggeredCellLoadReportingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggeredCellLoadReportingRequest, aper.DecodeState,

	) (EventTriggeredCellLoadReportingRequest, aper.Snapshot,

	)
	compare func(EventTriggeredCellLoadReportingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggeredCellLoadReportingRequestValueCodec) New(value EventTriggeredCellLoadReportingRequest,

) (EventTriggeredCellLoadReportingRequestAPERValue, error) {
	if c.encode == nil {
		return EventTriggeredCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggeredCellLoadReportingRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggeredCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggeredCellLoadReportingRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggeredCellLoadReportingRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggeredCellLoadReportingRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggeredCellLoadReportingRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggeredCellLoadReportingRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggeredCellLoadReportingRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggeredCellLoadReportingRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggeredCellLoadReportingRequestValueCodec) EncodeAPER(value EventTriggeredCellLoadReportingRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggeredCellLoadReportingRequestValueCodec) encodeBudgetValue(value EventTriggeredCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggeredCellLoadReportingRequestValueCodec) encodeChanged(value EventTriggeredCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggeredCellLoadReportingResponseValueCodec is the concrete ValueCodec[EventTriggeredCellLoadReportingResponse].
type EventTriggeredCellLoadReportingResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTriggeredCellLoadReportingResponse,

		error)
	encode func(EventTriggeredCellLoadReportingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTriggeredCellLoadReportingResponse, aper.DecodeState,

	) (EventTriggeredCellLoadReportingResponse, aper.Snapshot,

	)
	compare func(EventTriggeredCellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggeredCellLoadReportingResponseValueCodec) New(value EventTriggeredCellLoadReportingResponse,

) (EventTriggeredCellLoadReportingResponseAPERValue, error) {
	if c.encode == nil {
		return EventTriggeredCellLoadReportingResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggeredCellLoadReportingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggeredCellLoadReportingResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggeredCellLoadReportingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggeredCellLoadReportingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggeredCellLoadReportingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggeredCellLoadReportingResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggeredCellLoadReportingResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggeredCellLoadReportingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggeredCellLoadReportingResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggeredCellLoadReportingResponseValueCodec) EncodeAPER(value EventTriggeredCellLoadReportingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EventTriggeredCellLoadReportingResponseValueCodec) encodeBudgetValue(value EventTriggeredCellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggeredCellLoadReportingResponseValueCodec) encodeChanged(value EventTriggeredCellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExpectedUEActivityBehaviourValueCodec is the concrete ValueCodec[ExpectedUEActivityBehaviour].
type ExpectedUEActivityBehaviourValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviour,

		error)
	encode func(ExpectedUEActivityBehaviour,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ExpectedUEActivityBehaviour, aper.DecodeState,

	) (ExpectedUEActivityBehaviour, aper.Snapshot,

	)
	compare func(ExpectedUEActivityBehaviour, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExpectedUEActivityBehaviourValueCodec) New(value ExpectedUEActivityBehaviour,

) (ExpectedUEActivityBehaviourAPERValue, error) {
	if c.encode == nil {
		return ExpectedUEActivityBehaviourAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ExpectedUEActivityBehaviourAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ExpectedUEActivityBehaviourAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ExpectedUEActivityBehaviourAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExpectedUEActivityBehaviourValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ExpectedUEActivityBehaviourAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ExpectedUEActivityBehaviourAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ExpectedUEActivityBehaviourAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ExpectedUEActivityBehaviourAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ExpectedUEActivityBehaviourAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExpectedUEActivityBehaviourValueCodec) EncodeAPER(value ExpectedUEActivityBehaviourAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ExpectedUEActivityBehaviourValueCodec) encodeBudgetValue(value ExpectedUEActivityBehaviour,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExpectedUEActivityBehaviourValueCodec) encodeChanged(value ExpectedUEActivityBehaviour,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FiveGSTAIValueCodec is the concrete ValueCodec[FiveGSTAI].
type FiveGSTAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (FiveGSTAI,

		error)
	encode func(FiveGSTAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(FiveGSTAI, aper.DecodeState,

	) (FiveGSTAI, aper.Snapshot,

	)
	compare func(FiveGSTAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FiveGSTAIValueCodec) New(value FiveGSTAI,

) (FiveGSTAIAPERValue, error) {
	if c.encode == nil {
		return FiveGSTAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FiveGSTAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FiveGSTAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FiveGSTAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FiveGSTAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FiveGSTAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FiveGSTAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FiveGSTAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FiveGSTAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FiveGSTAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FiveGSTAIValueCodec) EncodeAPER(value FiveGSTAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FiveGSTAIValueCodec) encodeBudgetValue(value FiveGSTAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FiveGSTAIValueCodec) encodeChanged(value FiveGSTAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenLAsValueCodec is the concrete ValueCodec[ForbiddenLAs].
type ForbiddenLAsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenLAs,

		error)
	encode func(ForbiddenLAs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenLAs, aper.DecodeState,

	) (ForbiddenLAs, aper.Snapshot,

	)
	compare func(ForbiddenLAs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenLAsValueCodec) New(value ForbiddenLAs,

) (ForbiddenLAsAPERValue, error) {
	if c.encode == nil {
		return ForbiddenLAsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenLAsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenLAsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenLAsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenLAsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenLAsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenLAsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenLAsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenLAsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenLAsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenLAsValueCodec) EncodeAPER(value ForbiddenLAsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenLAsValueCodec) encodeBudgetValue(value ForbiddenLAs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenLAsValueCodec) encodeChanged(value ForbiddenLAs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenLAsItemValueCodec is the concrete ValueCodec[ForbiddenLAsItem].
type ForbiddenLAsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenLAsItem,

		error)
	encode func(ForbiddenLAsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenLAsItem, aper.DecodeState,

	) (ForbiddenLAsItem, aper.Snapshot,

	)
	compare func(ForbiddenLAsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenLAsItemValueCodec) New(value ForbiddenLAsItem,

) (ForbiddenLAsItemAPERValue, error) {
	if c.encode == nil {
		return ForbiddenLAsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenLAsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenLAsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenLAsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenLAsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenLAsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenLAsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenLAsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenLAsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenLAsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenLAsItemValueCodec) EncodeAPER(value ForbiddenLAsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenLAsItemValueCodec) encodeBudgetValue(value ForbiddenLAsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenLAsItemValueCodec) encodeChanged(value ForbiddenLAsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenTAsValueCodec is the concrete ValueCodec[ForbiddenTAs].
type ForbiddenTAsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenTAs,

		error)
	encode func(ForbiddenTAs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenTAs, aper.DecodeState,

	) (ForbiddenTAs, aper.Snapshot,

	)
	compare func(ForbiddenTAs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenTAsValueCodec) New(value ForbiddenTAs,

) (ForbiddenTAsAPERValue, error) {
	if c.encode == nil {
		return ForbiddenTAsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenTAsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenTAsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenTAsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenTAsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenTAsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenTAsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenTAsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenTAsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenTAsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenTAsValueCodec) EncodeAPER(value ForbiddenTAsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenTAsValueCodec) encodeBudgetValue(value ForbiddenTAs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenTAsValueCodec) encodeChanged(value ForbiddenTAs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenTAsItemValueCodec is the concrete ValueCodec[ForbiddenTAsItem].
type ForbiddenTAsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ForbiddenTAsItem,

		error)
	encode func(ForbiddenTAsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ForbiddenTAsItem, aper.DecodeState,

	) (ForbiddenTAsItem, aper.Snapshot,

	)
	compare func(ForbiddenTAsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenTAsItemValueCodec) New(value ForbiddenTAsItem,

) (ForbiddenTAsItemAPERValue, error) {
	if c.encode == nil {
		return ForbiddenTAsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenTAsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenTAsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenTAsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenTAsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenTAsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenTAsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenTAsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenTAsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenTAsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenTAsItemValueCodec) EncodeAPER(value ForbiddenTAsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenTAsItemValueCodec) encodeBudgetValue(value ForbiddenTAsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenTAsItemValueCodec) encodeChanged(value ForbiddenTAsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GBRQosInformationValueCodec is the concrete ValueCodec[GBRQosInformation].
type GBRQosInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GBRQosInformation,

		error)
	encode func(GBRQosInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GBRQosInformation, aper.DecodeState,

	) (GBRQosInformation, aper.Snapshot,

	)
	compare func(GBRQosInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GBRQosInformationValueCodec) New(value GBRQosInformation,

) (GBRQosInformationAPERValue, error) {
	if c.encode == nil {
		return GBRQosInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GBRQosInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GBRQosInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GBRQosInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GBRQosInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GBRQosInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GBRQosInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GBRQosInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GBRQosInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GBRQosInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GBRQosInformationValueCodec) EncodeAPER(value GBRQosInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GBRQosInformationValueCodec) encodeBudgetValue(value GBRQosInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GBRQosInformationValueCodec) encodeChanged(value GBRQosInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GERANCellIDValueCodec is the concrete ValueCodec[GERANCellID].
type GERANCellIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GERANCellID,

		error)
	encode func(GERANCellID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GERANCellID, aper.DecodeState,

	) (GERANCellID, aper.Snapshot,

	)
	compare func(GERANCellID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GERANCellIDValueCodec) New(value GERANCellID,

) (GERANCellIDAPERValue, error) {
	if c.encode == nil {
		return GERANCellIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GERANCellIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GERANCellIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GERANCellIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GERANCellIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GERANCellIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GERANCellIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GERANCellIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GERANCellIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GERANCellIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GERANCellIDValueCodec) EncodeAPER(value GERANCellIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GERANCellIDValueCodec) encodeBudgetValue(value GERANCellID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GERANCellIDValueCodec) encodeChanged(value GERANCellID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GNBValueCodec is the concrete ValueCodec[GNB].
type GNBValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GNB,

		error)
	encode func(GNB,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GNB, aper.DecodeState,

	) (GNB, aper.Snapshot,

	)
	compare func(GNB, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GNBValueCodec) New(value GNB,

) (GNBAPERValue, error) {
	if c.encode == nil {
		return GNBAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GNBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GNBAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GNBAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GNBValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GNBAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GNBAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GNBAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GNBAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GNBAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GNBValueCodec) EncodeAPER(value GNBAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GNBValueCodec) encodeBudgetValue(value GNB,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GNBValueCodec) encodeChanged(value GNB,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GNBIdentityValueCodec is the concrete ValueCodec[GNBIdentity].
type GNBIdentityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GNBIdentity,

		error)
	encode func(GNBIdentity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GNBIdentity, aper.DecodeState,

	) (GNBIdentity, aper.Snapshot,

	)
	compare func(GNBIdentity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GNBIdentityValueCodec) New(value GNBIdentity,

) (GNBIdentityAPERValue, error) {
	if c.encode == nil {
		return GNBIdentityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GNBIdentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GNBIdentityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GNBIdentityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GNBIdentityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GNBIdentityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GNBIdentityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GNBIdentityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GNBIdentityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GNBIdentityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GNBIdentityValueCodec) EncodeAPER(value GNBIdentityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GNBIdentityValueCodec) encodeBudgetValue(value GNBIdentity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GNBIdentityValueCodec) encodeChanged(value GNBIdentity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalEnGNBIDValueCodec is the concrete ValueCodec[GlobalEnGNBID].
type GlobalEnGNBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalEnGNBID,

		error)
	encode func(GlobalEnGNBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalEnGNBID, aper.DecodeState,

	) (GlobalEnGNBID, aper.Snapshot,

	)
	compare func(GlobalEnGNBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalEnGNBIDValueCodec) New(value GlobalEnGNBID,

) (GlobalEnGNBIDAPERValue, error) {
	if c.encode == nil {
		return GlobalEnGNBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalEnGNBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalEnGNBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalEnGNBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalEnGNBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalEnGNBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalEnGNBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalEnGNBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalEnGNBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalEnGNBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalEnGNBIDValueCodec) EncodeAPER(value GlobalEnGNBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GlobalEnGNBIDValueCodec) encodeBudgetValue(value GlobalEnGNBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalEnGNBIDValueCodec) encodeChanged(value GlobalEnGNBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalGNBIDValueCodec is the concrete ValueCodec[GlobalGNBID].
type GlobalGNBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalGNBID,

		error)
	encode func(GlobalGNBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalGNBID, aper.DecodeState,

	) (GlobalGNBID, aper.Snapshot,

	)
	compare func(GlobalGNBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalGNBIDValueCodec) New(value GlobalGNBID,

) (GlobalGNBIDAPERValue, error) {
	if c.encode == nil {
		return GlobalGNBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalGNBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalGNBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalGNBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalGNBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalGNBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalGNBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalGNBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalGNBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalGNBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalGNBIDValueCodec) EncodeAPER(value GlobalGNBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GlobalGNBIDValueCodec) encodeBudgetValue(value GlobalGNBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalGNBIDValueCodec) encodeChanged(value GlobalGNBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverSuccessValueCodec is the concrete ValueCodec[HandoverSuccess].
type HandoverSuccessValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverSuccess,

		error)
	encode func(HandoverSuccess,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverSuccess, aper.DecodeState,

	) (HandoverSuccess, aper.Snapshot,

	)
	compare func(HandoverSuccess, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverSuccessValueCodec) New(value HandoverSuccess,

) (HandoverSuccessAPERValue, error) {
	if c.encode == nil {
		return HandoverSuccessAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverSuccessAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverSuccessAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverSuccessAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverSuccessValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverSuccessAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverSuccessAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverSuccessAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverSuccessAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverSuccessAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverSuccessValueCodec) EncodeAPER(value HandoverSuccessAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverSuccessValueCodec) encodeBudgetValue(value HandoverSuccess,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverSuccessValueCodec) encodeChanged(value HandoverSuccess,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IEsECGIListValueCodec is the concrete ValueCodec[IEsECGIList].
type IEsECGIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IEsECGIList,

		error)
	encode func(IEsECGIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IEsECGIList, aper.DecodeState,

	) (IEsECGIList, aper.Snapshot,

	)
	compare func(IEsECGIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IEsECGIListValueCodec) New(value IEsECGIList,

) (IEsECGIListAPERValue, error) {
	if c.encode == nil {
		return IEsECGIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IEsECGIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IEsECGIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IEsECGIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IEsECGIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IEsECGIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IEsECGIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IEsECGIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IEsECGIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IEsECGIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IEsECGIListValueCodec) EncodeAPER(value IEsECGIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IEsECGIListValueCodec) encodeBudgetValue(value IEsECGIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IEsECGIListValueCodec) encodeChanged(value IEsECGIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IRATCellIDValueCodec is the concrete ValueCodec[IRATCellID].
type IRATCellIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IRATCellID,

		error)
	encode func(IRATCellID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IRATCellID, aper.DecodeState,

	) (IRATCellID, aper.Snapshot,

	)
	compare func(IRATCellID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IRATCellIDValueCodec) New(value IRATCellID,

) (IRATCellIDAPERValue, error) {
	if c.encode == nil {
		return IRATCellIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IRATCellIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IRATCellIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IRATCellIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IRATCellIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IRATCellIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IRATCellIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IRATCellIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IRATCellIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IRATCellIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IRATCellIDValueCodec) EncodeAPER(value IRATCellIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IRATCellIDValueCodec) encodeBudgetValue(value IRATCellID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IRATCellIDValueCodec) encodeChanged(value IRATCellID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementItemValueCodec is the concrete ValueCodec[InterSystemMeasurementItem].
type InterSystemMeasurementItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementItem,

		error)
	encode func(InterSystemMeasurementItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementItem, aper.DecodeState,

	) (InterSystemMeasurementItem, aper.Snapshot,

	)
	compare func(InterSystemMeasurementItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementItemValueCodec) New(value InterSystemMeasurementItem,

) (InterSystemMeasurementItemAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementItemValueCodec) EncodeAPER(value InterSystemMeasurementItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterSystemMeasurementItemValueCodec) encodeBudgetValue(value InterSystemMeasurementItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementItemValueCodec) encodeChanged(value InterSystemMeasurementItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementListValueCodec is the concrete ValueCodec[InterSystemMeasurementList].
type InterSystemMeasurementListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementList,

		error)
	encode func(InterSystemMeasurementList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementList, aper.DecodeState,

	) (InterSystemMeasurementList, aper.Snapshot,

	)
	compare func(InterSystemMeasurementList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementListValueCodec) New(value InterSystemMeasurementList,

) (InterSystemMeasurementListAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementListValueCodec) EncodeAPER(value InterSystemMeasurementListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterSystemMeasurementListValueCodec) encodeBudgetValue(value InterSystemMeasurementList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementListValueCodec) encodeChanged(value InterSystemMeasurementList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedGERANCellInformationValueCodec is the concrete ValueCodec[LastVisitedGERANCellInformation].
type LastVisitedGERANCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedGERANCellInformation,

		error)
	encode func(LastVisitedGERANCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedGERANCellInformation, aper.DecodeState,

	) (LastVisitedGERANCellInformation, aper.Snapshot,

	)
	compare func(LastVisitedGERANCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedGERANCellInformationValueCodec) New(value LastVisitedGERANCellInformation,

) (LastVisitedGERANCellInformationAPERValue, error) {
	if c.encode == nil {
		return LastVisitedGERANCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedGERANCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedGERANCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedGERANCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedGERANCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedGERANCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedGERANCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedGERANCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedGERANCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedGERANCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedGERANCellInformationValueCodec) EncodeAPER(value LastVisitedGERANCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedGERANCellInformationValueCodec) encodeBudgetValue(value LastVisitedGERANCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedGERANCellInformationValueCodec) encodeChanged(value LastVisitedGERANCellInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ListeningSubframePatternValueCodec is the concrete ValueCodec[ListeningSubframePattern].
type ListeningSubframePatternValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ListeningSubframePattern,

		error)
	encode func(ListeningSubframePattern,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ListeningSubframePattern, aper.DecodeState,

	) (ListeningSubframePattern, aper.Snapshot,

	)
	compare func(ListeningSubframePattern, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ListeningSubframePatternValueCodec) New(value ListeningSubframePattern,

) (ListeningSubframePatternAPERValue, error) {
	if c.encode == nil {
		return ListeningSubframePatternAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ListeningSubframePatternAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ListeningSubframePatternAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ListeningSubframePatternAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ListeningSubframePatternValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ListeningSubframePatternAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ListeningSubframePatternAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ListeningSubframePatternAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ListeningSubframePatternAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ListeningSubframePatternAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ListeningSubframePatternValueCodec) EncodeAPER(value ListeningSubframePatternAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ListeningSubframePatternValueCodec) encodeBudgetValue(value ListeningSubframePattern,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ListeningSubframePatternValueCodec) encodeChanged(value ListeningSubframePattern,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LTENTNTAIInformationAPERValue is the concrete APERValue[LTENTNTAIInformation].
type LTENTNTAIInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   LTENTNTAIInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LTENTNTAIInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTENTNTAIInformationAPERValue) WithoutReplay() LTENTNTAIInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABLevelQoSParametersAPERValue is the concrete APERValue[ERABLevelQoSParameters].
type ERABLevelQoSParametersAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABLevelQoSParameters

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABLevelQoSParametersAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABLevelQoSParametersAPERValue) WithoutReplay() ERABLevelQoSParametersAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GUMMEIAPERValue is the concrete APERValue[GUMMEI].
type GUMMEIAPERValue struct {
	context s00.BridgeCodecContext
	Value   GUMMEI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GUMMEIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIAPERValue) WithoutReplay() GUMMEIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEBehaviourAPERValue is the concrete APERValue[ExpectedUEBehaviour].
type ExpectedUEBehaviourAPERValue struct {
	context s00.BridgeCodecContext
	Value   ExpectedUEBehaviour

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEBehaviourAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEBehaviourAPERValue) WithoutReplay() ExpectedUEBehaviourAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LAIAPERValue is the concrete APERValue[LAI].
type LAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   LAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LAIAPERValue) WithoutReplay() LAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GUMMEIListAPERValue is the concrete APERValue[GUMMEIList].
type GUMMEIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   GUMMEIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GUMMEIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEIListAPERValue) WithoutReplay() GUMMEIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalENBIDAPERValue is the concrete APERValue[GlobalENBID].
type GlobalENBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   GlobalENBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalENBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalENBIDAPERValue) WithoutReplay() GlobalENBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AdditionalGUTIAPERValue is the concrete APERValue[AdditionalGUTI].
type AdditionalGUTIAPERValue struct {
	context s00.BridgeCodecContext
	Value   AdditionalGUTI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AdditionalGUTIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AdditionalGUTIAPERValue) WithoutReplay() AdditionalGUTIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CandidateCellListAPERValue is the concrete APERValue[CandidateCellList].
type CandidateCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CandidateCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CandidateCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CandidateCellListAPERValue) WithoutReplay() CandidateCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANcellLoadReportingResponseAPERValue is the concrete APERValue[EUTRANcellLoadReportingResponse].
type EUTRANcellLoadReportingResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s17.EUTRANcellLoadReportingResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EUTRANcellLoadReportingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANcellLoadReportingResponseAPERValue) WithoutReplay() EUTRANcellLoadReportingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggeredCellLoadReportingRequestAPERValue is the concrete APERValue[EventTriggeredCellLoadReportingRequest].
type EventTriggeredCellLoadReportingRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   EventTriggeredCellLoadReportingRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggeredCellLoadReportingRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggeredCellLoadReportingRequestAPERValue) WithoutReplay() EventTriggeredCellLoadReportingRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggeredCellLoadReportingResponseAPERValue is the concrete APERValue[EventTriggeredCellLoadReportingResponse].
type EventTriggeredCellLoadReportingResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   EventTriggeredCellLoadReportingResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggeredCellLoadReportingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggeredCellLoadReportingResponseAPERValue) WithoutReplay() EventTriggeredCellLoadReportingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ExpectedUEActivityBehaviourAPERValue is the concrete APERValue[ExpectedUEActivityBehaviour].
type ExpectedUEActivityBehaviourAPERValue struct {
	context s00.BridgeCodecContext
	Value   ExpectedUEActivityBehaviour

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ExpectedUEActivityBehaviourAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ExpectedUEActivityBehaviourAPERValue) WithoutReplay() ExpectedUEActivityBehaviourAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FiveGSTAIAPERValue is the concrete APERValue[FiveGSTAI].
type FiveGSTAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   FiveGSTAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FiveGSTAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTAIAPERValue) WithoutReplay() FiveGSTAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenLAsAPERValue is the concrete APERValue[ForbiddenLAs].
type ForbiddenLAsAPERValue struct {
	context s00.BridgeCodecContext
	Value   ForbiddenLAs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenLAsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsAPERValue) WithoutReplay() ForbiddenLAsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenLAsItemAPERValue is the concrete APERValue[ForbiddenLAsItem].
type ForbiddenLAsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ForbiddenLAsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenLAsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLAsItemAPERValue) WithoutReplay() ForbiddenLAsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenTAsAPERValue is the concrete APERValue[ForbiddenTAs].
type ForbiddenTAsAPERValue struct {
	context s00.BridgeCodecContext
	Value   ForbiddenTAs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenTAsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsAPERValue) WithoutReplay() ForbiddenTAsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenTAsItemAPERValue is the concrete APERValue[ForbiddenTAsItem].
type ForbiddenTAsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ForbiddenTAsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenTAsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTAsItemAPERValue) WithoutReplay() ForbiddenTAsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GBRQosInformationAPERValue is the concrete APERValue[GBRQosInformation].
type GBRQosInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   GBRQosInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GBRQosInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GBRQosInformationAPERValue) WithoutReplay() GBRQosInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GERANCellIDAPERValue is the concrete APERValue[GERANCellID].
type GERANCellIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   GERANCellID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GERANCellIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GERANCellIDAPERValue) WithoutReplay() GERANCellIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GNBAPERValue is the concrete APERValue[GNB].
type GNBAPERValue struct {
	context s00.BridgeCodecContext
	Value   GNB

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GNBAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBAPERValue) WithoutReplay() GNBAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GNBIdentityAPERValue is the concrete APERValue[GNBIdentity].
type GNBIdentityAPERValue struct {
	context s00.BridgeCodecContext
	Value   GNBIdentity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GNBIdentityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBIdentityAPERValue) WithoutReplay() GNBIdentityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalEnGNBIDAPERValue is the concrete APERValue[GlobalEnGNBID].
type GlobalEnGNBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   GlobalEnGNBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalEnGNBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalEnGNBIDAPERValue) WithoutReplay() GlobalEnGNBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalGNBIDAPERValue is the concrete APERValue[GlobalGNBID].
type GlobalGNBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   GlobalGNBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalGNBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalGNBIDAPERValue) WithoutReplay() GlobalGNBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverSuccessAPERValue is the concrete APERValue[HandoverSuccess].
type HandoverSuccessAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverSuccess

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverSuccessAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverSuccessAPERValue) WithoutReplay() HandoverSuccessAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IEsECGIListAPERValue is the concrete APERValue[IEsECGIList].
type IEsECGIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   IEsECGIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IEsECGIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IEsECGIListAPERValue) WithoutReplay() IEsECGIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IRATCellIDAPERValue is the concrete APERValue[IRATCellID].
type IRATCellIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   IRATCellID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IRATCellIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IRATCellIDAPERValue) WithoutReplay() IRATCellIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementItemAPERValue is the concrete APERValue[InterSystemMeasurementItem].
type InterSystemMeasurementItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterSystemMeasurementItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementItemAPERValue) WithoutReplay() InterSystemMeasurementItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementListAPERValue is the concrete APERValue[InterSystemMeasurementList].
type InterSystemMeasurementListAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterSystemMeasurementList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementListAPERValue) WithoutReplay() InterSystemMeasurementListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedGERANCellInformationAPERValue is the concrete APERValue[LastVisitedGERANCellInformation].
type LastVisitedGERANCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   LastVisitedGERANCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedGERANCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedGERANCellInformationAPERValue) WithoutReplay() LastVisitedGERANCellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ListeningSubframePatternAPERValue is the concrete APERValue[ListeningSubframePattern].
type ListeningSubframePatternAPERValue struct {
	context s00.BridgeCodecContext
	Value   ListeningSubframePattern

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ListeningSubframePatternAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ListeningSubframePatternAPERValue) WithoutReplay() ListeningSubframePatternAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelIEValueERABIEContainerList, error)
	encode  func(HandoverCancelIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelIEValueERABIEContainerList, aper.DecodeState) (HandoverCancelIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverCancelIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelIEValueERABIEContainerListValueCodec) New(value HandoverCancelIEValueERABIEContainerList) (HandoverCancelIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverCancelIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverCancelIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverCancelIEValue].
type HandoverCancelIEValueERABIEContainerList []HandoverCancelIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueERABIEContainerList, error)
	encode  func(LocationReportingFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) New(value LocationReportingFailureIndicationIEValueERABIEContainerList) (LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value LocationReportingFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value LocationReportingFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueERABIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// HandoverCancelIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverCancelIEValue]].
type HandoverCancelIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelIEField, error)
	encode  func(HandoverCancelIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelIEField, aper.DecodeState) (HandoverCancelIEField, aper.Snapshot)
	compare func(HandoverCancelIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelIEFieldValueCodec) New(value HandoverCancelIEField) (HandoverCancelIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelIEFieldValueCodec) EncodeAPER(value HandoverCancelIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelIEFieldValueCodec) encodeBudgetValue(value HandoverCancelIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelIEFieldValueCodec) encodeChanged(value HandoverCancelIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEField, error)
	encode  func(LocationReportingFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndicationIEField, aper.DecodeState) (LocationReportingFailureIndicationIEField, aper.Snapshot)
	compare func(LocationReportingFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationIEFieldValueCodec) New(value LocationReportingFailureIndicationIEField) (LocationReportingFailureIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationIEFieldValueCodec) EncodeAPER(value LocationReportingFailureIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingFailureIndicationIEFieldValueCodec) encodeBudgetValue(value LocationReportingFailureIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationIEFieldValueCodec) encodeChanged(value LocationReportingFailureIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverCancelIEValue]].
type HandoverCancelIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelIEContainer, error)
	encode  func(HandoverCancelIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelIEContainer, aper.DecodeState) (HandoverCancelIEContainer, aper.Snapshot)
	compare func(HandoverCancelIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelIEContainerValueCodec) New(value HandoverCancelIEContainer) (HandoverCancelIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelIEContainerValueCodec) EncodeAPER(value HandoverCancelIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelIEContainerValueCodec) encodeBudgetValue(value HandoverCancelIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelIEContainerValueCodec) encodeChanged(value HandoverCancelIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEContainer, error)
	encode  func(LocationReportingFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndicationIEContainer, aper.DecodeState) (LocationReportingFailureIndicationIEContainer, aper.Snapshot)
	compare func(LocationReportingFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationIEContainerValueCodec) New(value LocationReportingFailureIndicationIEContainer) (LocationReportingFailureIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationIEContainerValueCodec) EncodeAPER(value LocationReportingFailureIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingFailureIndicationIEContainerValueCodec) encodeBudgetValue(value LocationReportingFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationIEContainerValueCodec) encodeChanged(value LocationReportingFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverCancelIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverCancelIEValueProtocolErrorIEContainerList) (HandoverCancelIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverCancelIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverCancelIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverCancelIEValue].
type HandoverCancelIEValueProtocolErrorIEContainerList []HandoverCancelIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// HandoverCancelIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverCancelIEValueProtocolIEContainerList, error)
	encode  func(HandoverCancelIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverCancelIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverCancelIEValueProtocolIEContainerListValueCodec) New(value HandoverCancelIEValueProtocolIEContainerList) (HandoverCancelIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverCancelIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverCancelIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverCancelIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverCancelIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverCancelIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverCancelIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverCancelIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverCancelIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverCancelIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverCancelIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverCancelIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverCancelIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverCancelIEValue].
type HandoverCancelIEValueProtocolIEContainerList []HandoverCancelIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueProtocolIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// HandoverCancelIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverCancelIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverCancelIEValue].
type HandoverCancelIEValueProtocolIESingleContainer = HandoverCancelIEField

// LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingFailureIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[LocationReportingFailureIndicationIEValue].
type LocationReportingFailureIndicationIEValueProtocolIESingleContainer = LocationReportingFailureIndicationIEField

// HandoverCancelIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverCancelIEValue]].
type HandoverCancelIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEFieldAPERValue) WithoutReplay() HandoverCancelIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingFailureIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEFieldAPERValue) WithoutReplay() LocationReportingFailureIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverCancelIEValue]].
type HandoverCancelIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEContainerAPERValue) WithoutReplay() HandoverCancelIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingFailureIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEContainerAPERValue) WithoutReplay() LocationReportingFailureIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverCancelIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverCancelIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverCancelIEValue]].
type HandoverCancelIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverCancelIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverCancelIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverCancelIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverCancelIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[LocationReportingFailureIndicationIEValue]].
type LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         LocationReportingFailureIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APAdditionalGUTI(v *AdditionalGUTI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APGUMMEI(&v.GUMMEI, s)
	s00.BridgeCaptureS1APMTMSI(&v.MTMSI, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAdditionalGUTIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAdditionalGUTI(v *AdditionalGUTI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APGUMMEI(&v.GUMMEI, s)
	s02.BridgeCompareS1APMTMSI(&v.MTMSI, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeAdditionalGUTIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABLevelQoSParameters(v *ERABLevelQoSParameters, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APQCI(&v.QCI, s)
	s14.BridgeCaptureS1APAllocationAndRetentionPriority(&v.AllocationRetentionPriority, s)
	{
		f := s.Begin()
		s.Bool(v.GbrQosInformation == nil)
		if v.GbrQosInformation != nil {
			BridgeCaptureS1APGBRQosInformation(v.GbrQosInformation, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABQoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABLevelQoSParameters(v *ERABLevelQoSParameters, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s06.BridgeCompareS1APQCI(&v.QCI, s)
	s14.BridgeCompareS1APAllocationAndRetentionPriority(&v.AllocationRetentionPriority, s)
	{
		f := s.Begin()
		s.Bool(v.GbrQosInformation == nil)
		if v.GbrQosInformation != nil {
			BridgeCompareS1APGBRQosInformation(v.GbrQosInformation, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABQoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEventTriggeredCellLoadReportingRequest(v *EventTriggeredCellLoadReportingRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APNumberOfMeasurementReportingLevels(&v.NumberOfMeasurementReportingLevels, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEventTriggeredCellLoadReportingRequest(v *EventTriggeredCellLoadReportingRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APNumberOfMeasurementReportingLevels(&v.NumberOfMeasurementReportingLevels, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEventTriggeredCellLoadReportingResponse(v *EventTriggeredCellLoadReportingResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCaptureS1APCellLoadReportingResponse(&v.CellLoadReportingResponse, s)
	{
		f := s.Begin()
		s.Bool(v.OverloadFlag == nil)
		if v.OverloadFlag != nil {
			s00.BridgeCaptureS1APOverloadFlag(v.OverloadFlag, s)
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEventTriggeredCellLoadReportingResponse(v *EventTriggeredCellLoadReportingResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCompareS1APCellLoadReportingResponse(&v.CellLoadReportingResponse, s)
	{
		f := s.Begin()
		s.Bool(v.OverloadFlag == nil)
		if v.OverloadFlag != nil {
			s02.BridgeCompareS1APOverloadFlag(v.OverloadFlag, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APExpectedUEActivityBehaviour(v *ExpectedUEActivityBehaviour, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APExpectedActivityPeriod(&v.ExpectedActivityPeriod, s)
	s00.BridgeCaptureS1APExpectedIdlePeriod(&v.ExpectedIdlePeriod, s)
	{
		f := s.Begin()
		s.Bool(v.SourceofUEActivityBehaviourInformation == nil)
		if v.SourceofUEActivityBehaviourInformation != nil {
			s00.BridgeCaptureS1APSourceOfUEActivityBehaviourInformation(v.SourceofUEActivityBehaviourInformation, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeExpectedUEActivityBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APExpectedUEActivityBehaviour(v *ExpectedUEActivityBehaviour, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APExpectedActivityPeriod(&v.ExpectedActivityPeriod, s)
	s02.BridgeCompareS1APExpectedIdlePeriod(&v.ExpectedIdlePeriod, s)
	{
		f := s.Begin()
		s.Bool(v.SourceofUEActivityBehaviourInformation == nil)
		if v.SourceofUEActivityBehaviourInformation != nil {
			s07.BridgeCompareS1APSourceOfUEActivityBehaviourInformation(v.SourceofUEActivityBehaviourInformation, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeExpectedUEActivityBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APExpectedUEBehaviour(v *ExpectedUEBehaviour, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ExpectedActivity == nil)
		if v.ExpectedActivity != nil {
			BridgeCaptureS1APExpectedUEActivityBehaviour(v.ExpectedActivity, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ExpectedHOInterval == nil)
		if v.ExpectedHOInterval != nil {
			s00.BridgeCaptureS1APExpectedHOInterval(v.ExpectedHOInterval, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeExpectedUEBehaviourExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APExpectedUEBehaviour(v *ExpectedUEBehaviour, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ExpectedActivity == nil)
		if v.ExpectedActivity != nil {
			BridgeCompareS1APExpectedUEActivityBehaviour(v.ExpectedActivity, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ExpectedHOInterval == nil)
		if v.ExpectedHOInterval != nil {
			s02.BridgeCompareS1APExpectedHOInterval(v.ExpectedHOInterval, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeExpectedUEBehaviourExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APFiveGSTAI(v *FiveGSTAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APFiveGSTAC(&v.FiveGSTAC, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeFiveGSTAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APFiveGSTAI(v *FiveGSTAI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APFiveGSTAC(&v.FiveGSTAC, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeFiveGSTAIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenLAsItem(v *ForbiddenLAsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APForbiddenLACs(&v.ForbiddenLACs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeForbiddenLAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenLAsItem(v *ForbiddenLAsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s02.BridgeCompareS1APForbiddenLACs(&v.ForbiddenLACs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeForbiddenLAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenTAsItem(v *ForbiddenTAsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APForbiddenTACs(&v.ForbiddenTACs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeForbiddenTAsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APForbiddenTAsItem(v *ForbiddenTAsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s07.BridgeCompareS1APForbiddenTACs(&v.ForbiddenTACs, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeForbiddenTAsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGBRQosInformation(v *GBRQosInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.ERABMaximumBitrateDL, s)
	s00.BridgeCaptureS1APBitRate(&v.ERABMaximumBitrateUL, s)
	s00.BridgeCaptureS1APBitRate(&v.ERABGuaranteedBitrateDL, s)
	s00.BridgeCaptureS1APBitRate(&v.ERABGuaranteedBitrateUL, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGBRQosInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGBRQosInformation(v *GBRQosInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.ERABMaximumBitrateDL, s)
	s02.BridgeCompareS1APBitRate(&v.ERABMaximumBitrateUL, s)
	s02.BridgeCompareS1APBitRate(&v.ERABGuaranteedBitrateDL, s)
	s02.BridgeCompareS1APBitRate(&v.ERABGuaranteedBitrateUL, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGBRQosInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGERANCellID(v *GERANCellID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APLAI(&v.LAI, s)
	s00.BridgeCaptureS1APRAC(&v.RAC, s)
	s00.BridgeCaptureS1APCI(&v.CI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGERANCellID(v *GERANCellID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APLAI(&v.LAI, s)
	s06.BridgeCompareS1APRAC(&v.RAC, s)
	s02.BridgeCompareS1APCI(&v.CI, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGNB(v *GNB, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APGlobalGNBID(&v.GlobalGNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGNBExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGNB(v *GNB, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APGlobalGNBID(&v.GlobalGNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGNBExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGNBIdentity(v *GNBIdentity, s *aper.SemanticCapture) {
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
	case s00.GNBIdentityChoiceGNBID:
		{
			f := s.Begin()
			s.Bool(v.GNBID == nil)
			if v.GNBID != nil {
				s00.BridgeCaptureS1APGNBID(v.GNBID, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGNBIdentity(v *GNBIdentity, s *aper.SemanticComparison) {
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
	case s00.GNBIdentityChoiceGNBID:
		{
			f := s.Begin()
			s.Bool(v.GNBID == nil)
			if v.GNBID != nil {
				s02.BridgeCompareS1APGNBID(v.GNBID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGUMMEI(v *GUMMEI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APMMEGroupID(&v.MMEGroupID, s)
	s00.BridgeCaptureS1APMMECode(&v.MMECode, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGUMMEIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGUMMEI(v *GUMMEI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s02.BridgeCompareS1APMMEGroupID(&v.MMEGroupID, s)
	s02.BridgeCompareS1APMMECode(&v.MMECode, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGUMMEIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGlobalENBID(v *GlobalENBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s15.BridgeCaptureS1APENBID(&v.ENBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalENBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGlobalENBID(v *GlobalENBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s15.BridgeCompareS1APENBID(&v.ENBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalENBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGlobalEnGNBID(v *GlobalEnGNBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APEnGNBID(&v.EnGNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalEnGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGlobalEnGNBID(v *GlobalEnGNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APEnGNBID(&v.EnGNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalEnGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGlobalGNBID(v *GlobalGNBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	BridgeCaptureS1APGNBIdentity(&v.GNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalGNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGlobalGNBID(v *GlobalGNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	BridgeCompareS1APGNBIdentity(&v.GNBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeGlobalGNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverCancelIEValue(v *HandoverCancelIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverCancelIEValue) captureSemantics(s aper.SemanticCapture) HandoverCancelIEValue {
	BridgeCaptureS1APHandoverCancelIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverCancelIEValue(v *HandoverCancelIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverCancelIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverCancelIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APHandoverSuccess(v *HandoverSuccess, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeHandoverSuccessIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverSuccess(v *HandoverSuccess, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeHandoverSuccessIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APIRATCellID(v *IRATCellID, s *aper.SemanticCapture) {
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
	case s00.IRATCellIDChoiceEUTRAN:
		s.Bytes(v.EUTRAN)
	case s00.IRATCellIDChoiceUTRAN:
		s.Bytes(v.UTRAN)
	case s00.IRATCellIDChoiceGERAN:
		s.Bytes(v.GERAN)
	case s00.IRATCellIDChoiceEHRPD:
		{
			f := s.Begin()
			s.Bool(v.EHRPD == nil)
			if v.EHRPD != nil {
				s00.BridgeCaptureS1APEHRPDSectorID(v.EHRPD, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APIRATCellID(v *IRATCellID, s *aper.SemanticComparison) {
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
	case s00.IRATCellIDChoiceEUTRAN:
		s.Bytes(v.EUTRAN)
	case s00.IRATCellIDChoiceUTRAN:
		s.Bytes(v.UTRAN)
	case s00.IRATCellIDChoiceGERAN:
		s.Bytes(v.GERAN)
	case s00.IRATCellIDChoiceEHRPD:
		{
			f := s.Begin()
			s.Bool(v.EHRPD == nil)
			if v.EHRPD != nil {
				s02.BridgeCompareS1APEHRPDSectorID(v.EHRPD, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APInterSystemMeasurementItem(v *InterSystemMeasurementItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.FreqBandIndicatorNR))
	s.Int(int64(v.SSBfrequencies))
	s.Int(int64(v.SubcarrierSpacingSSB))
	{
		f := s.Begin()
		s.Bool(v.MaxRSIndexCellQual == nil)
		if v.MaxRSIndexCellQual != nil {
			s.Int(int64((*v.MaxRSIndexCellQual)))
		}
		s.End(f, nil, false)
	}
	s.Bool(v.SMTC == nil)
	s.Bytes(v.SMTC)
	s.Bool(v.ThreshRSIndexR15 == nil)
	s.Bytes(v.ThreshRSIndexR15)
	s.Bool(v.SSBToMeasure == nil)
	s.Bytes(v.SSBToMeasure)
	s.Bool(v.SSRSSIMeasurement == nil)
	s.Bytes(v.SSRSSIMeasurement)
	s.Bool(v.QuantityConfigNRR15 == nil)
	s.Bytes(v.QuantityConfigNRR15)
	s.Bool(v.ExcludedCellsToAddModList == nil)
	s.Bytes(v.ExcludedCellsToAddModList)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInterSystemMeasurementItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInterSystemMeasurementItem(v *InterSystemMeasurementItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.FreqBandIndicatorNR))
	s.Int(int64(v.SSBfrequencies))
	s.Int(int64(v.SubcarrierSpacingSSB))
	{
		f := s.Begin()
		s.Bool(v.MaxRSIndexCellQual == nil)
		if v.MaxRSIndexCellQual != nil {
			s.Int(int64((*v.MaxRSIndexCellQual)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.SMTC == nil)
	s.Bytes(v.SMTC)
	s.Bool(v.ThreshRSIndexR15 == nil)
	s.Bytes(v.ThreshRSIndexR15)
	s.Bool(v.SSBToMeasure == nil)
	s.Bytes(v.SSBToMeasure)
	s.Bool(v.SSRSSIMeasurement == nil)
	s.Bytes(v.SSRSSIMeasurement)
	s.Bool(v.QuantityConfigNRR15 == nil)
	s.Bytes(v.QuantityConfigNRR15)
	s.Bool(v.ExcludedCellsToAddModList == nil)
	s.Bytes(v.ExcludedCellsToAddModList)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInterSystemMeasurementItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLAI(v *LAI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APLAC(&v.LAC, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLAI(v *LAI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APLAC(&v.LAC, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLTENTNTAIInformation(v *LTENTNTAIInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.ServingPLMN, s)
	s00.BridgeCaptureS1APTACListInLTENTN(&v.TACListInLTENTN, s)
	{
		f := s.Begin()
		s.Bool(v.UELocationDerivedTAC == nil)
		if v.UELocationDerivedTAC != nil {
			s00.BridgeCaptureS1APTAC(v.UELocationDerivedTAC, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLTENTNTAIInformation(v *LTENTNTAIInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.ServingPLMN, s)
	s07.BridgeCompareS1APTACListInLTENTN(&v.TACListInLTENTN, s)
	{
		f := s.Begin()
		s.Bool(v.UELocationDerivedTAC == nil)
		if v.UELocationDerivedTAC != nil {
			s07.BridgeCompareS1APTAC(v.UELocationDerivedTAC, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLastVisitedGERANCellInformation(v *LastVisitedGERANCellInformation, s *aper.SemanticCapture) {
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
	case s00.LastVisitedGERANCellInformationChoiceUndefined:
		{
			f := s.Begin()
			s.Bool(v.Undefined == nil)
			if v.Undefined != nil {
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedGERANCellInformation(v *LastVisitedGERANCellInformation, s *aper.SemanticComparison) {
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
	case s00.LastVisitedGERANCellInformationChoiceUndefined:
		{
			f := s.Begin()
			s.Bool(v.Undefined == nil)
			if v.Undefined != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APListeningSubframePattern(v *ListeningSubframePattern, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PatternPeriod))
	{
		f := s.Begin()
		s.BigInt(v.PatternOffset)
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APListeningSubframePattern(v *ListeningSubframePattern, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PatternPeriod))
	{
		f := s.Begin()
		s.BigInt(v.PatternOffset)
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReportingFailureIndicationIEValue(v *LocationReportingFailureIndicationIEValue, s *aper.SemanticCapture) {
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LocationReportingFailureIndicationIEValue) captureSemantics(s aper.SemanticCapture) LocationReportingFailureIndicationIEValue {
	BridgeCaptureS1APLocationReportingFailureIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APLocationReportingFailureIndicationIEValue(v *LocationReportingFailureIndicationIEValue, s *aper.SemanticComparison) {
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v LocationReportingFailureIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APLocationReportingFailureIndicationIEValue(&v, &s)
	return s
}

// AdditionalGUTI represents the ASN.1 type Additional-GUTI (SEQUENCE).
type AdditionalGUTI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GUMMEI            GUMMEI                               `asn1:"tag:0,context,implicit"`
	MTMSI             s00.MTMSI                            `asn1:"tag:1,context,implicit"`
	IEExtensions      s07.AdditionalGUTIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type IEsECGIList = []s17.EUTRANCGI

// GERANCellID represents the ASN.1 type GERAN-Cell-ID (SEQUENCE).
type GERANCellID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	LAI               LAI                               `asn1:"tag:0,context,implicit"`
	RAC               s00.RAC                           `asn1:"tag:1,context,implicit"`
	CI                s00.CI                            `asn1:"tag:2,context,implicit"`
	IEExtensions      s09.GERANCellIDExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// GlobalENBID represents the ASN.1 type Global-ENB-ID (SEQUENCE).
type GlobalENBID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity                  `asn1:"tag:0,context,implicit"`
	ENBID             s15.ENBID                         `asn1:"tag:1,context,explicit"`
	IEExtensions      s09.GlobalENBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// GlobalEnGNBID represents the ASN.1 type Global-en-gNB-ID (SEQUENCE).
type GlobalEnGNBID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity                    `asn1:"tag:0,context,implicit"`
	EnGNBID           s00.EnGNBID                         `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.GlobalEnGNBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                `asn1:"-" json:"-"`
	extCount          int64                               `asn1:"-" json:"-"`
	extPresent        []bool                              `asn1:"-" json:"-"`
	extData           [][]byte                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type GUMMEIList = []GUMMEI

// ERABLevelQoSParameters represents the ASN.1 type E-RABLevelQoSParameters (SEQUENCE).
type ERABLevelQoSParameters struct {
	replay                      aper.Snapshot
	stream                      aper.WireSpan
	received                    bool
	withoutReplay               bool
	receivedAbsolute            bool
	receivedBytes               aper.WireSpan
	receivedLocation            aper.Location
	QCI                         s00.QCI                                 `asn1:"tag:0,context,implicit"`
	AllocationRetentionPriority s14.AllocationAndRetentionPriority      `asn1:"tag:1,context,implicit"`
	GbrQosInformation           *GBRQosInformation                      `asn1:"tag:2,context,implicit,optional" json:"GbrQosInformation,omitempty"`
	IEExtensions                s08.ERABQoSParametersExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef           bool                                    `asn1:"-" json:"-"`
	extCount                    int64                                   `asn1:"-" json:"-"`
	extPresent                  []bool                                  `asn1:"-" json:"-"`
	extData                     [][]byte                                `asn1:"-" json:"-"`
	perPadding                  aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding               []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin                   []aper.OpaqueOrigin
	extWire                     []aper.WireSpan
}

// ExpectedUEBehaviour represents the ASN.1 type ExpectedUEBehaviour (SEQUENCE).
type ExpectedUEBehaviour struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	ExpectedActivity   *ExpectedUEActivityBehaviour              `asn1:"tag:0,context,implicit,optional" json:"ExpectedActivity,omitempty"`
	ExpectedHOInterval *s00.ExpectedHOInterval                   `asn1:"tag:1,context,implicit,optional" json:"ExpectedHOInterval,omitempty"`
	IEExtensions       s09.ExpectedUEBehaviourExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                      `asn1:"-" json:"-"`
	extCount           int64                                     `asn1:"-" json:"-"`
	extPresent         []bool                                    `asn1:"-" json:"-"`
	extData            [][]byte                                  `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// ExpectedUEActivityBehaviour represents the ASN.1 type ExpectedUEActivityBehaviour (SEQUENCE).
type ExpectedUEActivityBehaviour struct {
	replay                                 aper.Snapshot
	stream                                 aper.WireSpan
	received                               bool
	withoutReplay                          bool
	receivedAbsolute                       bool
	receivedBytes                          aper.WireSpan
	receivedLocation                       aper.Location
	ExpectedActivityPeriod                 s00.ExpectedActivityPeriod                        `asn1:"tag:0,context,implicit,optional" json:"ExpectedActivityPeriod,omitzero"`
	ExpectedIdlePeriod                     s00.ExpectedIdlePeriod                            `asn1:"tag:1,context,implicit,optional" json:"ExpectedIdlePeriod,omitzero"`
	SourceofUEActivityBehaviourInformation *s00.SourceOfUEActivityBehaviourInformation       `asn1:"tag:2,context,implicit,optional" json:"SourceofUEActivityBehaviourInformation,omitempty"`
	IEExtensions                           s09.ExpectedUEActivityBehaviourExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                      bool                                              `asn1:"-" json:"-"`
	extCount                               int64                                             `asn1:"-" json:"-"`
	extPresent                             []bool                                            `asn1:"-" json:"-"`
	extData                                [][]byte                                          `asn1:"-" json:"-"`
	perPadding                             aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding                          []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin                              []aper.OpaqueOrigin
	extWire                                []aper.WireSpan
}

// FiveGSTAI represents the ASN.1 type FiveGSTAI (SEQUENCE).
type FiveGSTAI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity                `asn1:"tag:0,context,implicit"`
	FiveGSTAC         s00.FiveGSTAC                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.FiveGSTAIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                            `asn1:"-" json:"-"`
	extCount          int64                           `asn1:"-" json:"-"`
	extPresent        []bool                          `asn1:"-" json:"-"`
	extData           [][]byte                        `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ForbiddenTAs = []ForbiddenTAsItem

// ForbiddenTAsItem represents the ASN.1 type ForbiddenTAs-Item (SEQUENCE).
type ForbiddenTAsItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	PLMNIdentity       s00.PLMNidentity                       `asn1:"tag:0,context,implicit"`
	ForbiddenTACs      s00.ForbiddenTACs                      `asn1:"tag:1,context,implicit"`
	forbiddenTACsIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions       s09.ForbiddenTAsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                   `asn1:"-" json:"-"`
	extCount           int64                                  `asn1:"-" json:"-"`
	extPresent         []bool                                 `asn1:"-" json:"-"`
	extData            [][]byte                               `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type ForbiddenLAs = []ForbiddenLAsItem

// ForbiddenLAsItem represents the ASN.1 type ForbiddenLAs-Item (SEQUENCE).
type ForbiddenLAsItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	PLMNIdentity       s00.PLMNidentity                       `asn1:"tag:0,context,implicit"`
	ForbiddenLACs      s00.ForbiddenLACs                      `asn1:"tag:1,context,implicit"`
	forbiddenLACsIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions       s09.ForbiddenLAsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                   `asn1:"-" json:"-"`
	extCount           int64                                  `asn1:"-" json:"-"`
	extPresent         []bool                                 `asn1:"-" json:"-"`
	extData            [][]byte                               `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// GBRQosInformation represents the ASN.1 type GBR-QosInformation (SEQUENCE).
type GBRQosInformation struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	ERABMaximumBitrateDL    s00.BitRate                             `asn1:"tag:0,context,implicit"`
	ERABMaximumBitrateUL    s00.BitRate                             `asn1:"tag:1,context,implicit"`
	ERABGuaranteedBitrateDL s00.BitRate                             `asn1:"tag:2,context,implicit"`
	ERABGuaranteedBitrateUL s00.BitRate                             `asn1:"tag:3,context,implicit"`
	IEExtensions            s09.GBRQosInformationExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                    `asn1:"-" json:"-"`
	extCount                int64                                   `asn1:"-" json:"-"`
	extPresent              []bool                                  `asn1:"-" json:"-"`
	extData                 [][]byte                                `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// GUMMEI represents the ASN.1 type GUMMEI (SEQUENCE).
type GUMMEI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNIdentity      s00.PLMNidentity             `asn1:"tag:0,context,implicit"`
	MMEGroupID        s00.MMEGroupID               `asn1:"tag:1,context,implicit"`
	MMECode           s00.MMECode                  `asn1:"tag:2,context,implicit"`
	IEExtensions      s09.GUMMEIExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                         `asn1:"-" json:"-"`
	extCount          int64                        `asn1:"-" json:"-"`
	extPresent        []bool                       `asn1:"-" json:"-"`
	extData           [][]byte                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type InterSystemMeasurementList = []InterSystemMeasurementItem

// InterSystemMeasurementItem represents the ASN.1 type InterSystemMeasurementItem (SEQUENCE).
type InterSystemMeasurementItem struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	FreqBandIndicatorNR       int64                                            `asn1:"tag:0,context,implicit"`
	SSBfrequencies            int64                                            `asn1:"tag:1,context,implicit"`
	SubcarrierSpacingSSB      int64                                            `asn1:"tag:2,context,implicit"`
	MaxRSIndexCellQual        *int64                                           `asn1:"tag:3,context,implicit,optional" json:"MaxRSIndexCellQual,omitempty"`
	SMTC                      []byte                                           `asn1:"tag:4,context,implicit,optional" json:"SMTC,omitzero"`
	ThreshRSIndexR15          []byte                                           `asn1:"tag:5,context,implicit,optional" json:"ThreshRSIndexR15,omitzero"`
	SSBToMeasure              []byte                                           `asn1:"tag:6,context,implicit,optional" json:"SSBToMeasure,omitzero"`
	SSRSSIMeasurement         []byte                                           `asn1:"tag:7,context,implicit,optional" json:"SSRSSIMeasurement,omitzero"`
	QuantityConfigNRR15       []byte                                           `asn1:"tag:8,context,implicit,optional" json:"QuantityConfigNRR15,omitzero"`
	ExcludedCellsToAddModList []byte                                           `asn1:"tag:9,context,implicit,optional" json:"ExcludedCellsToAddModList,omitzero"`
	IEExtensions              s09.InterSystemMeasurementItemExtIEsExtContainer `asn1:"tag:10,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                             `asn1:"-" json:"-"`
	perPadding                aper.CompletePadding                             `asn1:"-" json:"-"`
}

// LAI represents the ASN.1 type LAI (SEQUENCE).
type LAI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity          `asn1:"tag:0,context,implicit"`
	LAC               s00.LAC                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.LAIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                      `asn1:"-" json:"-"`
	extCount          int64                     `asn1:"-" json:"-"`
	extPresent        []bool                    `asn1:"-" json:"-"`
	extData           [][]byte                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// LastVisitedGERANCellInformation represents the ASN.1 CHOICE type LastVisitedGERANCellInformation.
type LastVisitedGERANCellInformation struct {
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
	Undefined          *struct{}             `json:"Undefined,omitempty"`
}

// ListeningSubframePattern represents the ASN.1 type ListeningSubframePattern (SEQUENCE).
type ListeningSubframePattern struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PatternPeriod     int64                                          `asn1:"tag:0,context,implicit"`
	PatternOffset     *big.Int                                       `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.ListeningSubframePatternExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                           `asn1:"-" json:"-"`
	extCount          int64                                          `asn1:"-" json:"-"`
	extPresent        []bool                                         `asn1:"-" json:"-"`
	extData           [][]byte                                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// LTENTNTAIInformation represents the ASN.1 type LTE-NTN-TAI-Information (SEQUENCE).
type LTENTNTAIInformation struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	ServingPLMN          s00.PLMNidentity                           `asn1:"tag:0,context,implicit"`
	TACListInLTENTN      s00.TACListInLTENTN                        `asn1:"tag:1,context,implicit"`
	tACListInLTENTNIndef bool                                       `asn1:"-" json:"-"`
	UELocationDerivedTAC *s00.TAC                                   `asn1:"tag:2,context,implicit,optional" json:"UELocationDerivedTAC,omitempty"`
	IEExtensions         s09.LTENTNTAIInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                       `asn1:"-" json:"-"`
	extCount             int64                                      `asn1:"-" json:"-"`
	extPresent           []bool                                     `asn1:"-" json:"-"`
	extData              [][]byte                                   `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// GNB represents the ASN.1 type GNB (SEQUENCE).
type GNB struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalGNBID       GlobalGNBID               `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.GNBExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                      `asn1:"-" json:"-"`
	extCount          int64                     `asn1:"-" json:"-"`
	extPresent        []bool                    `asn1:"-" json:"-"`
	extData           [][]byte                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// GlobalGNBID represents the ASN.1 type Global-GNB-ID (SEQUENCE).
type GlobalGNBID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNIdentity      s00.PLMNidentity                  `asn1:"tag:0,context,implicit"`
	GNBID             GNBIdentity                       `asn1:"tag:1,context,explicit"`
	IEExtensions      s09.GlobalGNBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// GNBIdentity represents the ASN.1 CHOICE type GNB-Identity.
type GNBIdentity struct {
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
	GNBID              *s00.GNBID            `json:"GNBID,omitempty"`
}

// MarshalAPER encodes AdditionalGUTI to APER format.
func (v *AdditionalGUTI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AdditionalGUTI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.GUMMEI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding gUMMEI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.MTMSI), 4, 4, true); err != nil {
		return fmt.Errorf("encoding m-TMSI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeAdditionalGUTIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AdditionalGUTI from APER format.
func (v *AdditionalGUTI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AdditionalGUTI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AdditionalGUTI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AdditionalGUTI")
	}
	bb.EnterComponent("AdditionalGUTI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AdditionalGUTI")
	}
	padding, err := aper.CaptureFinalBits(bb, "AdditionalGUTI")
	if err != nil {
		return runtime.WrapDecodePath(err, "AdditionalGUTI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AdditionalGUTI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AdditionalGUTI{}
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
	toleranceMark_gummei := bb.EnterComponent("GUMMEI")
	if err := v.GUMMEI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GUMMEI")
	}
	bb.LeaveComponent(toleranceMark_gummei)
	val_mtmsi, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "MTMSI")
	}
	v.MTMSI = s00.MTMSI(val_mtmsi)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s07.AdditionalGUTIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.AdditionalGUTIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeAdditionalGUTIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GERANCellID to APER format.
func (v *GERANCellID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GERANCellID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.LAI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding lAI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.RAC), 1, 1, true); err != nil {
		return fmt.Errorf("encoding rAC: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.CI), 2, 2, true); err != nil {
		return fmt.Errorf("encoding cI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GERANCellID from APER format.
func (v *GERANCellID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GERANCellID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GERANCellID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GERANCellID")
	}
	bb.EnterComponent("GERANCellID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GERANCellID")
	}
	padding, err := aper.CaptureFinalBits(bb, "GERANCellID")
	if err != nil {
		return runtime.WrapDecodePath(err, "GERANCellID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GERANCellID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GERANCellID{}
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
	toleranceMark_lai := bb.EnterComponent("LAI")
	if err := v.LAI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LAI")
	}
	bb.LeaveComponent(toleranceMark_lai)
	val_rac, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "RAC")
	}
	v.RAC = s00.RAC(val_rac)
	val_ci, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CI")
	}
	v.CI = s00.CI(val_ci)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GERANCellIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GERANCellIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GlobalENBID to APER format.
func (v *GlobalENBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GlobalENBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := s15.BridgeENBIDMethodMarshalAPERTo(&v.ENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eNB-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GlobalENBID from APER format.
func (v *GlobalENBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GlobalENBID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GlobalENBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	bb.EnterComponent("GlobalENBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "GlobalENBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GlobalENBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalENBID{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	toleranceMark_enbid := bb.EnterComponent("ENBID")
	if err := s15.BridgeENBIDMethodUnmarshalAPERFrom(&v.ENBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBID")
	}
	bb.LeaveComponent(toleranceMark_enbid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GlobalENBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GlobalENBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGlobalENBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GlobalEnGNBID to APER format.
func (v *GlobalEnGNBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GlobalEnGNBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.EnGNBID.Bytes, v.EnGNBID.BitLength, 22, 32, true, true); err != nil {
		return fmt.Errorf("encoding en-gNB-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GlobalEnGNBID from APER format.
func (v *GlobalEnGNBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GlobalEnGNBID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GlobalEnGNBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GlobalEnGNBID")
	}
	bb.EnterComponent("GlobalEnGNBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalEnGNBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "GlobalEnGNBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "GlobalEnGNBID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GlobalEnGNBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalEnGNBID{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	bsBytes_engnbid, bsBitLen_engnbid, err := aper.DecodeBitStringAlignedExt(bb, 22, 32, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EnGNBID")
	}
	v.EnGNBID = runtime.BitString{Bytes: bsBytes_engnbid, BitLength: bsBitLen_engnbid}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GlobalEnGNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GlobalEnGNBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGlobalEnGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABLevelQoSParameters to APER format.
func (v *ERABLevelQoSParameters) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABLevelQoSParameters) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.GbrQosInformation != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.QCI), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding qCI: %w", err)
	}
	if err := s14.BridgeAllocationAndRetentionPriorityMethodMarshalAPERTo(&v.AllocationRetentionPriority, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding allocationRetentionPriority: %w", err)
	}
	if v.GbrQosInformation != nil {
		if err := v.GbrQosInformation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding gbrQosInformation: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABLevelQoSParameters from APER format.
func (v *ERABLevelQoSParameters) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABLevelQoSParameters with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABLevelQoSParameters) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
	}
	bb.EnterComponent("ERABLevelQoSParameters")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABLevelQoSParameters")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABLevelQoSParameters")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABLevelQoSParameters) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABLevelQoSParameters{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_gbrqosinformation, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_qci, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "QCI")
	}
	v.QCI = s00.QCI(val_qci)
	toleranceMark_allocationretentionpriority := bb.EnterComponent("AllocationRetentionPriority")
	if err := s14.BridgeAllocationAndRetentionPriorityMethodUnmarshalAPERFrom(&v.AllocationRetentionPriority, bb); err != nil {
		return runtime.WrapDecodePath(err, "AllocationRetentionPriority")
	}
	bb.LeaveComponent(toleranceMark_allocationretentionpriority)
	if opt_gbrqosinformation {
		toleranceMark_gbrqosinformation := bb.EnterComponent("GbrQosInformation")
		var dec_gbrqosinformation GBRQosInformation
		if err := dec_gbrqosinformation.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "GbrQosInformation")
		}
		if err := aper.ChargeValue(bb, dec_gbrqosinformation); err != nil {
			return err
		}
		v.GbrQosInformation = &dec_gbrqosinformation
		bb.LeaveComponent(toleranceMark_gbrqosinformation)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ERABQoSParametersExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABQoSParametersExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeERABQoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ExpectedUEBehaviour to APER format.
func (v *ExpectedUEBehaviour) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ExpectedUEBehaviour) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ExpectedActivity != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ExpectedHOInterval != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ExpectedActivity != nil {
		if err := v.ExpectedActivity.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding expectedActivity: %w", err)
		}
	}
	if v.ExpectedHOInterval != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.ExpectedHOInterval), 7, true); err != nil {
			return fmt.Errorf("encoding expectedHOInterval: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ExpectedUEBehaviour from APER format.
func (v *ExpectedUEBehaviour) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ExpectedUEBehaviour with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ExpectedUEBehaviour) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEBehaviour")
	}
	bb.EnterComponent("ExpectedUEBehaviour")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEBehaviour")
	}
	padding, err := aper.CaptureFinalBits(bb, "ExpectedUEBehaviour")
	if err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEBehaviour")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ExpectedUEBehaviour) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEBehaviour{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_expectedactivity, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_expectedhointerval, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_expectedactivity {
		toleranceMark_expectedactivity := bb.EnterComponent("ExpectedActivity")
		var dec_expectedactivity ExpectedUEActivityBehaviour
		if err := dec_expectedactivity.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "ExpectedActivity")
		}
		if err := aper.ChargeValue(bb, dec_expectedactivity); err != nil {
			return err
		}
		v.ExpectedActivity = &dec_expectedactivity
		bb.LeaveComponent(toleranceMark_expectedactivity)
	}
	if opt_expectedhointerval {
		val_expectedhointerval, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ExpectedHOInterval"})
		if err != nil {
			return runtime.WrapDecodePath(err, "ExpectedHOInterval")
		}
		tmp_expectedhointerval := s00.ExpectedHOInterval(val_expectedhointerval)
		if err := aper.ChargeValue(bb, tmp_expectedhointerval); err != nil {
			return err
		}
		v.ExpectedHOInterval = (*s00.ExpectedHOInterval)(bb.OwnInt64(int64(tmp_expectedhointerval)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ExpectedUEBehaviourExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ExpectedUEBehaviourExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeExpectedUEBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ExpectedUEActivityBehaviour to APER format.
func (v *ExpectedUEActivityBehaviour) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ExpectedUEActivityBehaviour) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ExpectedActivityPeriod != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ExpectedIdlePeriod != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SourceofUEActivityBehaviourInformation != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ExpectedActivityPeriod != nil {
		if err := aper.EncodeIntegerValueSetBigAligned(bb, v.ExpectedActivityPeriod, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true); err != nil {
			return fmt.Errorf("encoding expectedActivityPeriod: %w", err)
		}
	}
	if v.ExpectedIdlePeriod != nil {
		if err := aper.EncodeIntegerValueSetBigAligned(bb, v.ExpectedIdlePeriod, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true); err != nil {
			return fmt.Errorf("encoding expectedIdlePeriod: %w", err)
		}
	}
	if v.SourceofUEActivityBehaviourInformation != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.SourceofUEActivityBehaviourInformation), 2, true); err != nil {
			return fmt.Errorf("encoding sourceofUEActivityBehaviourInformation: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ExpectedUEActivityBehaviour from APER format.
func (v *ExpectedUEActivityBehaviour) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ExpectedUEActivityBehaviour with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ExpectedUEActivityBehaviour) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviour")
	}
	bb.EnterComponent("ExpectedUEActivityBehaviour")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviour")
	}
	padding, err := aper.CaptureFinalBits(bb, "ExpectedUEActivityBehaviour")
	if err != nil {
		return runtime.WrapDecodePath(err, "ExpectedUEActivityBehaviour")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ExpectedUEActivityBehaviour) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ExpectedUEActivityBehaviour{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_expectedactivityperiod, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_expectedidleperiod, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sourceofueactivitybehaviourinformation, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_expectedactivityperiod {
		val_expectedactivityperiod, err := aper.DecodeIntegerValueSetBigAligned(bb, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExpectedActivityPeriod")
		}
		v.ExpectedActivityPeriod = val_expectedactivityperiod
	}
	if opt_expectedidleperiod {
		val_expectedidleperiod, err := aper.DecodeIntegerValueSetBigAligned(bb, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExpectedIdlePeriod")
		}
		v.ExpectedIdlePeriod = val_expectedidleperiod
	}
	if opt_sourceofueactivitybehaviourinformation {
		val_sourceofueactivitybehaviourinformation, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SourceofUEActivityBehaviourInformation"})
		if err != nil {
			return runtime.WrapDecodePath(err, "SourceofUEActivityBehaviourInformation")
		}
		tmp_sourceofueactivitybehaviourinformation := s00.SourceOfUEActivityBehaviourInformation(val_sourceofueactivitybehaviourinformation)
		if err := aper.ChargeValue(bb, tmp_sourceofueactivitybehaviourinformation); err != nil {
			return err
		}
		v.SourceofUEActivityBehaviourInformation = (*s00.SourceOfUEActivityBehaviourInformation)(bb.OwnInt64(int64(tmp_sourceofueactivitybehaviourinformation)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ExpectedUEActivityBehaviourExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ExpectedUEActivityBehaviourExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeExpectedUEActivityBehaviourExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes FiveGSTAI to APER format.
func (v *FiveGSTAI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *FiveGSTAI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.FiveGSTAC), 3, 3, true); err != nil {
		return fmt.Errorf("encoding fiveGSTAC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes FiveGSTAI from APER format.
func (v *FiveGSTAI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes FiveGSTAI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *FiveGSTAI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "FiveGSTAI")
	}
	bb.EnterComponent("FiveGSTAI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "FiveGSTAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "FiveGSTAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "FiveGSTAI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *FiveGSTAI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = FiveGSTAI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	val_fivegstac, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "FiveGSTAC")
	}
	v.FiveGSTAC = s00.FiveGSTAC(val_fivegstac)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.FiveGSTAIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.FiveGSTAIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeFiveGSTAIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ForbiddenTAsItem to APER format.
func (v *ForbiddenTAsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ForbiddenTAsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ForbiddenTACs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_forbiddentacs, fragmentLength_forbiddentacs int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_forbiddentacs < 0 || fragmentOffset_forbiddentacs > int64(len(v.ForbiddenTACs)) || fragmentLength_forbiddentacs < 0 || fragmentLength_forbiddentacs > int64(len(v.ForbiddenTACs[fragmentOffset_forbiddentacs:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ForbiddenTACs[fragmentOffset_forbiddentacs : fragmentOffset_forbiddentacs+fragmentLength_forbiddentacs] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding forbiddenTACs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding forbiddenTACs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ForbiddenTAsItem from APER format.
func (v *ForbiddenTAsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenTAsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenTAsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAsItem")
	}
	bb.EnterComponent("ForbiddenTAsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenTAsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenTAsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ForbiddenTAsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenTAsItem{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	toleranceMark_forbiddentacs := bb.EnterComponent("ForbiddenTACs")
	v.ForbiddenTACs = make(s00.ForbiddenTACs, 0)
	_, errCollection_forbiddentacs := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_forbiddentacs, fragmentLength_forbiddentacs int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_forbiddentacs < 0 || fragmentLength_forbiddentacs < 0 || fragmentLength_forbiddentacs > int64(^uint(0)>>1) || fragmentOffset_forbiddentacs > int64(^uint(0)>>1)-fragmentLength_forbiddentacs {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_forbiddentacs; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenTACs[%d]", fragmentOffset_forbiddentacs+i))
			}
			if next, err := aper.AppendValues(bb, v.ForbiddenTACs, val); err != nil {
				return err
			} else {
				v.ForbiddenTACs = next
			}
		}
		return nil
	})
	if errCollection_forbiddentacs != nil {
		return runtime.WrapDecodePath(errCollection_forbiddentacs, "ForbiddenTACs")
	}
	bb.LeaveComponent(toleranceMark_forbiddentacs)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ForbiddenTAsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ForbiddenTAsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeForbiddenTAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ForbiddenLAsItem to APER format.
func (v *ForbiddenLAsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ForbiddenLAsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ForbiddenLACs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_forbiddenlacs, fragmentLength_forbiddenlacs int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_forbiddenlacs < 0 || fragmentOffset_forbiddenlacs > int64(len(v.ForbiddenLACs)) || fragmentLength_forbiddenlacs < 0 || fragmentLength_forbiddenlacs > int64(len(v.ForbiddenLACs[fragmentOffset_forbiddenlacs:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ForbiddenLACs[fragmentOffset_forbiddenlacs : fragmentOffset_forbiddenlacs+fragmentLength_forbiddenlacs] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding forbiddenLACs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding forbiddenLACs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ForbiddenLAsItem from APER format.
func (v *ForbiddenLAsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ForbiddenLAsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ForbiddenLAsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAsItem")
	}
	bb.EnterComponent("ForbiddenLAsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ForbiddenLAsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ForbiddenLAsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ForbiddenLAsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ForbiddenLAsItem{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	toleranceMark_forbiddenlacs := bb.EnterComponent("ForbiddenLACs")
	v.ForbiddenLACs = make(s00.ForbiddenLACs, 0)
	_, errCollection_forbiddenlacs := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4096, HasUpper: true}, true, func(fragmentOffset_forbiddenlacs, fragmentLength_forbiddenlacs int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_forbiddenlacs < 0 || fragmentLength_forbiddenlacs < 0 || fragmentLength_forbiddenlacs > int64(^uint(0)>>1) || fragmentOffset_forbiddenlacs > int64(^uint(0)>>1)-fragmentLength_forbiddenlacs {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_forbiddenlacs; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenLACs[%d]", fragmentOffset_forbiddenlacs+i))
			}
			if next, err := aper.AppendValues(bb, v.ForbiddenLACs, val); err != nil {
				return err
			} else {
				v.ForbiddenLACs = next
			}
		}
		return nil
	})
	if errCollection_forbiddenlacs != nil {
		return runtime.WrapDecodePath(errCollection_forbiddenlacs, "ForbiddenLACs")
	}
	bb.LeaveComponent(toleranceMark_forbiddenlacs)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ForbiddenLAsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ForbiddenLAsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeForbiddenLAsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GBRQosInformation to APER format.
func (v *GBRQosInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GBRQosInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.ERABMaximumBitrateDL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding e-RAB-MaximumBitrateDL: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ERABMaximumBitrateUL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding e-RAB-MaximumBitrateUL: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ERABGuaranteedBitrateDL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding e-RAB-GuaranteedBitrateDL: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ERABGuaranteedBitrateUL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding e-RAB-GuaranteedBitrateUL: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GBRQosInformation from APER format.
func (v *GBRQosInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GBRQosInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GBRQosInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GBRQosInformation")
	}
	bb.EnterComponent("GBRQosInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GBRQosInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "GBRQosInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "GBRQosInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GBRQosInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GBRQosInformation{}
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
	val_erabmaximumbitratedl, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABMaximumBitrateDL")
	}
	v.ERABMaximumBitrateDL = s00.BitRate(val_erabmaximumbitratedl)
	val_erabmaximumbitrateul, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABMaximumBitrateUL")
	}
	v.ERABMaximumBitrateUL = s00.BitRate(val_erabmaximumbitrateul)
	val_erabguaranteedbitratedl, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABGuaranteedBitrateDL")
	}
	v.ERABGuaranteedBitrateDL = s00.BitRate(val_erabguaranteedbitratedl)
	val_erabguaranteedbitrateul, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABGuaranteedBitrateUL")
	}
	v.ERABGuaranteedBitrateUL = s00.BitRate(val_erabguaranteedbitrateul)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GBRQosInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GBRQosInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGBRQosInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GUMMEI to APER format.
func (v *GUMMEI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GUMMEI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.MMEGroupID), 2, 2, true); err != nil {
		return fmt.Errorf("encoding mME-Group-ID: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.MMECode), 1, 1, true); err != nil {
		return fmt.Errorf("encoding mME-Code: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGUMMEIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GUMMEI from APER format.
func (v *GUMMEI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GUMMEI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GUMMEI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GUMMEI")
	}
	bb.EnterComponent("GUMMEI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GUMMEI")
	}
	padding, err := aper.CaptureFinalBits(bb, "GUMMEI")
	if err != nil {
		return runtime.WrapDecodePath(err, "GUMMEI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GUMMEI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GUMMEI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	val_mmegroupid, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEGroupID")
	}
	v.MMEGroupID = s00.MMEGroupID(val_mmegroupid)
	val_mmecode, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "MMECode")
	}
	v.MMECode = s00.MMECode(val_mmecode)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GUMMEIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GUMMEIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGUMMEIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes InterSystemMeasurementItem to APER format.
func (v *InterSystemMeasurementItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InterSystemMeasurementItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MaxRSIndexCellQual != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SMTC != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ThreshRSIndexR15 != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SSBToMeasure != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SSRSSIMeasurement != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.QuantityConfigNRR15 != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ExcludedCellsToAddModList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.FreqBandIndicatorNR), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(1024), false); err != nil {
		return fmt.Errorf("encoding freqBandIndicatorNR: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.SSBfrequencies), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(3279165), false); err != nil {
		return fmt.Errorf("encoding sSBfrequencies: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SubcarrierSpacingSSB), 5, true); err != nil {
		return fmt.Errorf("encoding subcarrierSpacingSSB: %w", err)
	}
	if v.MaxRSIndexCellQual != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MaxRSIndexCellQual), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(16), false); err != nil {
			return fmt.Errorf("encoding maxRSIndexCellQual: %w", err)
		}
	}
	if v.SMTC != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.SMTC, 0, 0, false); err != nil {
			return fmt.Errorf("encoding sMTC: %w", err)
		}
	}
	if v.ThreshRSIndexR15 != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.ThreshRSIndexR15, 0, 0, false); err != nil {
			return fmt.Errorf("encoding threshRS-Index-r15: %w", err)
		}
	}
	if v.SSBToMeasure != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.SSBToMeasure, 0, 0, false); err != nil {
			return fmt.Errorf("encoding sSBToMeasure: %w", err)
		}
	}
	if v.SSRSSIMeasurement != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.SSRSSIMeasurement, 0, 0, false); err != nil {
			return fmt.Errorf("encoding sSRSSIMeasurement: %w", err)
		}
	}
	if v.QuantityConfigNRR15 != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.QuantityConfigNRR15, 0, 0, false); err != nil {
			return fmt.Errorf("encoding quantityConfigNR-R15: %w", err)
		}
	}
	if v.ExcludedCellsToAddModList != nil {
		if err := aper.EncodeOctetStringAligned(bb, v.ExcludedCellsToAddModList, 0, 0, false); err != nil {
			return fmt.Errorf("encoding excludedCellsToAddModList: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InterSystemMeasurementItem from APER format.
func (v *InterSystemMeasurementItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterSystemMeasurementItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterSystemMeasurementItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementItem")
	}
	bb.EnterComponent("InterSystemMeasurementItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementItem")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InterSystemMeasurementItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementItem{}
	// Read preamble bitmap for optional root fields
	opt_maxrsindexcellqual, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_smtc, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_threshrsindexr15, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssbtomeasure, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssrssimeasurement, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_quantityconfignrr15, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_excludedcellstoaddmodlist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_freqbandindicatornr, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(1024), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "FreqBandIndicatorNR")
	}
	v.FreqBandIndicatorNR = val_freqbandindicatornr
	val_ssbfrequencies, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(3279165), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SSBfrequencies")
	}
	v.SSBfrequencies = val_ssbfrequencies
	val_subcarrierspacingssb, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 2, Path: "SubcarrierSpacingSSB"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SubcarrierSpacingSSB")
	}
	v.SubcarrierSpacingSSB = val_subcarrierspacingssb
	if opt_maxrsindexcellqual {
		val_maxrsindexcellqual, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(16), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MaxRSIndexCellQual")
		}
		if err := aper.ChargeValue(bb, val_maxrsindexcellqual); err != nil {
			return err
		}
		v.MaxRSIndexCellQual = (*int64)(bb.OwnInt64(int64(val_maxrsindexcellqual)))

	}
	if opt_smtc {
		val_smtc, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SMTC")
		}
		tmp_smtc := val_smtc
		v.SMTC = tmp_smtc
	}
	if opt_threshrsindexr15 {
		val_threshrsindexr15, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThreshRSIndexR15")
		}
		tmp_threshrsindexr15 := val_threshrsindexr15
		v.ThreshRSIndexR15 = tmp_threshrsindexr15
	}
	if opt_ssbtomeasure {
		val_ssbtomeasure, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSBToMeasure")
		}
		tmp_ssbtomeasure := val_ssbtomeasure
		v.SSBToMeasure = tmp_ssbtomeasure
	}
	if opt_ssrssimeasurement {
		val_ssrssimeasurement, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSRSSIMeasurement")
		}
		tmp_ssrssimeasurement := val_ssrssimeasurement
		v.SSRSSIMeasurement = tmp_ssrssimeasurement
	}
	if opt_quantityconfignrr15 {
		val_quantityconfignrr15, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "QuantityConfigNRR15")
		}
		tmp_quantityconfignrr15 := val_quantityconfignrr15
		v.QuantityConfigNRR15 = tmp_quantityconfignrr15
	}
	if opt_excludedcellstoaddmodlist {
		val_excludedcellstoaddmodlist, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExcludedCellsToAddModList")
		}
		tmp_excludedcellstoaddmodlist := val_excludedcellstoaddmodlist
		v.ExcludedCellsToAddModList = tmp_excludedcellstoaddmodlist
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.InterSystemMeasurementItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.InterSystemMeasurementItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeInterSystemMeasurementItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LAI to APER format.
func (v *LAI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LAI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.LAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding lAC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LAI from APER format.
func (v *LAI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LAI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LAI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LAI")
	}
	bb.EnterComponent("LAI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "LAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "LAI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LAI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LAI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	val_lac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "LAC")
	}
	v.LAC = s00.LAC(val_lac)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.LAIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.LAIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LastVisitedGERANCellInformation to APER format.
func (v *LastVisitedGERANCellInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *LastVisitedGERANCellInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "LastVisitedGERANCellInformation:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "LastVisitedGERANCellInformation:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "LastVisitedGERANCellInformation:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "LastVisitedGERANCellInformation:", v.Choice)
	}
	switch v.Choice {
	case s00.LastVisitedGERANCellInformationChoiceUndefined:
	default:
		return fmt.Errorf("unknown LastVisitedGERANCellInformation choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LastVisitedGERANCellInformation from APER format.
func (v *LastVisitedGERANCellInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LastVisitedGERANCellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LastVisitedGERANCellInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedGERANCellInformation")
	}
	bb.EnterComponent("LastVisitedGERANCellInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedGERANCellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "LastVisitedGERANCellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedGERANCellInformation")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *LastVisitedGERANCellInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedGERANCellInformation{}
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
	v.Choice = 1
	switch v.Choice {
	case s00.LastVisitedGERANCellInformationChoiceUndefined:
		v.Undefined = new(struct{})
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ListeningSubframePattern to APER format.
func (v *ListeningSubframePattern) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ListeningSubframePattern) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PatternPeriod), 4, true); err != nil {
		return fmt.Errorf("encoding pattern-period: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PatternOffset, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound4, true); err != nil {
		return fmt.Errorf("encoding pattern-offset: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ListeningSubframePattern from APER format.
func (v *ListeningSubframePattern) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ListeningSubframePattern with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ListeningSubframePattern) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ListeningSubframePattern")
	}
	bb.EnterComponent("ListeningSubframePattern")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ListeningSubframePattern")
	}
	padding, err := aper.CaptureFinalBits(bb, "ListeningSubframePattern")
	if err != nil {
		return runtime.WrapDecodePath(err, "ListeningSubframePattern")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ListeningSubframePattern) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ListeningSubframePattern{}
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
	val_patternperiod, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PatternPeriod"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PatternPeriod")
	}
	v.PatternPeriod = val_patternperiod
	val_patternoffset, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PatternOffset")
	}
	v.PatternOffset = val_patternoffset
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ListeningSubframePatternExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ListeningSubframePatternExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LTENTNTAIInformation to APER format.
func (v *LTENTNTAIInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LTENTNTAIInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.UELocationDerivedTAC != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.ServingPLMN), 3, 3, true); err != nil {
		return fmt.Errorf("encoding servingPLMN: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.TACListInLTENTN)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 12, HasUpper: true}, true, func(fragmentOffset_taclistinltentn, fragmentLength_taclistinltentn int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_taclistinltentn < 0 || fragmentOffset_taclistinltentn > int64(len(v.TACListInLTENTN)) || fragmentLength_taclistinltentn < 0 || fragmentLength_taclistinltentn > int64(len(v.TACListInLTENTN[fragmentOffset_taclistinltentn:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.TACListInLTENTN[fragmentOffset_taclistinltentn : fragmentOffset_taclistinltentn+fragmentLength_taclistinltentn] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 2, 2, true); err != nil {
				return fmt.Errorf("encoding tACList-In-LTE-NTN element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding tACList-In-LTE-NTN: %w", err)
	}
	if v.UELocationDerivedTAC != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.UELocationDerivedTAC), 2, 2, true); err != nil {
			return fmt.Errorf("encoding uE-Location-Derived-TAC: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LTENTNTAIInformation from APER format.
func (v *LTENTNTAIInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LTENTNTAIInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LTENTNTAIInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LTENTNTAIInformation")
	}
	bb.EnterComponent("LTENTNTAIInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LTENTNTAIInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "LTENTNTAIInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "LTENTNTAIInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LTENTNTAIInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LTENTNTAIInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_uelocationderivedtac, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_servingplmn, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServingPLMN")
	}
	v.ServingPLMN = s00.PLMNidentity(val_servingplmn)
	toleranceMark_taclistinltentn := bb.EnterComponent("TACListInLTENTN")
	v.TACListInLTENTN = make(s00.TACListInLTENTN, 0)
	_, errCollection_taclistinltentn := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 12, HasUpper: true}, true, func(fragmentOffset_taclistinltentn, fragmentLength_taclistinltentn int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_taclistinltentn < 0 || fragmentLength_taclistinltentn < 0 || fragmentLength_taclistinltentn > int64(^uint(0)>>1) || fragmentOffset_taclistinltentn > int64(^uint(0)>>1)-fragmentLength_taclistinltentn {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_taclistinltentn; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("TACListInLTENTN[%d]", fragmentOffset_taclistinltentn+i))
			}
			if next, err := aper.AppendValues(bb, v.TACListInLTENTN, val); err != nil {
				return err
			} else {
				v.TACListInLTENTN = next
			}
		}
		return nil
	})
	if errCollection_taclistinltentn != nil {
		return runtime.WrapDecodePath(errCollection_taclistinltentn, "TACListInLTENTN")
	}
	bb.LeaveComponent(toleranceMark_taclistinltentn)
	if opt_uelocationderivedtac {
		val_uelocationderivedtac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UELocationDerivedTAC")
		}
		tmp_uelocationderivedtac := s00.TAC(val_uelocationderivedtac)
		if err := aper.ChargeValue(bb, tmp_uelocationderivedtac); err != nil {
			return err
		}
		v.UELocationDerivedTAC = &tmp_uelocationderivedtac
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.LTENTNTAIInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.LTENTNTAIInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GNB to APER format.
func (v *GNB) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GNB) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.GlobalGNBID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-gNB-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGNBExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GNB from APER format.
func (v *GNB) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GNB with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GNB) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GNB")
	}
	bb.EnterComponent("GNB")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GNB")
	}
	padding, err := aper.CaptureFinalBits(bb, "GNB")
	if err != nil {
		return runtime.WrapDecodePath(err, "GNB")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GNB) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GNB{}
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
	toleranceMark_globalgnbid := bb.EnterComponent("GlobalGNBID")
	if err := v.GlobalGNBID.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalGNBID")
	}
	bb.LeaveComponent(toleranceMark_globalgnbid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GNBExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GNBExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGNBExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GlobalGNBID to APER format.
func (v *GlobalGNBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *GlobalGNBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := v.GNBID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding gNB-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GlobalGNBID from APER format.
func (v *GlobalGNBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GlobalGNBID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GlobalGNBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GlobalGNBID")
	}
	bb.EnterComponent("GlobalGNBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalGNBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "GlobalGNBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "GlobalGNBID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *GlobalGNBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalGNBID{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNidentity(val_plmnidentity)
	toleranceMark_gnbid := bb.EnterComponent("GNBID")
	if err := v.GNBID.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GNBID")
	}
	bb.LeaveComponent(toleranceMark_gnbid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.GlobalGNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.GlobalGNBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeGlobalGNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GNBIdentity to APER format.
func (v *GNBIdentity) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *GNBIdentity) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "GNBIdentity:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "GNBIdentity:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "GNBIdentity:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "GNBIdentity:", v.Choice)
	}
	switch v.Choice {
	case s00.GNBIdentityChoiceGNBID:
		if v.GNBID == nil {
			return fmt.Errorf("choice alternative gNB-ID is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.GNBID.Bytes, v.GNBID.BitLength, 22, 32, true); err != nil {
			return fmt.Errorf("encoding gNB-ID: %w", err)
		}
	default:
		return fmt.Errorf("unknown GNBIdentity choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes GNBIdentity from APER format.
func (v *GNBIdentity) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GNBIdentity with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GNBIdentity) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GNBIdentity")
	}
	bb.EnterComponent("GNBIdentity")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GNBIdentity")
	}
	padding, err := aper.CaptureFinalBits(bb, "GNBIdentity")
	if err != nil {
		return runtime.WrapDecodePath(err, "GNBIdentity")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *GNBIdentity) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GNBIdentity{}
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
	v.Choice = 1
	switch v.Choice {
	case s00.GNBIdentityChoiceGNBID:
		bsBytes_gnbid, bsBitLen_gnbid, err := aper.DecodeBitStringAligned(bb, 22, 32, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "GNBID")
		}
		tmp_gnbid := runtime.BitString{Bytes: bsBytes_gnbid, BitLength: bsBitLen_gnbid}
		if err := aper.ChargeValue(bb, tmp_gnbid); err != nil {
			return err
		}
		v.GNBID = &tmp_gnbid
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AdditionalGUTI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AdditionalGUTI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AdditionalGUTI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AdditionalGUTI) WithoutReplay() AdditionalGUTI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AdditionalGUTI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABLevelQoSParameters) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABLevelQoSParameters", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABLevelQoSParameters", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABLevelQoSParameters) WithoutReplay() ERABLevelQoSParameters {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABLevelQoSParameters
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ExpectedUEActivityBehaviour) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ExpectedUEActivityBehaviour", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ExpectedUEActivityBehaviour", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ExpectedUEActivityBehaviour) WithoutReplay() ExpectedUEActivityBehaviour {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ExpectedUEActivityBehaviour
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ExpectedUEBehaviour) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ExpectedUEBehaviour", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ExpectedUEBehaviour", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ExpectedUEBehaviour) WithoutReplay() ExpectedUEBehaviour {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ExpectedUEBehaviour
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *FiveGSTAI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "FiveGSTAI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "FiveGSTAI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v FiveGSTAI) WithoutReplay() FiveGSTAI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero FiveGSTAI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenLAsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenLAsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenLAsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenLAsItem) WithoutReplay() ForbiddenLAsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenLAsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ForbiddenTAsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ForbiddenTAsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ForbiddenTAsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ForbiddenTAsItem) WithoutReplay() ForbiddenTAsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ForbiddenTAsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GBRQosInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GBRQosInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GBRQosInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GBRQosInformation) WithoutReplay() GBRQosInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GBRQosInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GERANCellID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GERANCellID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GERANCellID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GERANCellID) WithoutReplay() GERANCellID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GERANCellID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GNB) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GNB", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GNB", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GNB) WithoutReplay() GNB {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GNB
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GNBIdentity) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GNBIdentity", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GNBIdentity", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GNBIdentity) WithoutReplay() GNBIdentity {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GNBIdentity
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GUMMEI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GUMMEI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GUMMEI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GUMMEI) WithoutReplay() GUMMEI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GUMMEI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GlobalENBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GlobalENBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GlobalENBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GlobalENBID) WithoutReplay() GlobalENBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GlobalENBID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GlobalEnGNBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GlobalEnGNBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GlobalEnGNBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GlobalEnGNBID) WithoutReplay() GlobalEnGNBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GlobalEnGNBID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GlobalGNBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GlobalGNBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GlobalGNBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GlobalGNBID) WithoutReplay() GlobalGNBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GlobalGNBID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterSystemMeasurementItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemMeasurementItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InterSystemMeasurementItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterSystemMeasurementItem) WithoutReplay() InterSystemMeasurementItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InterSystemMeasurementItem
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LAI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LAI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LAI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LAI) WithoutReplay() LAI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LAI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LTENTNTAIInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LTENTNTAIInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LTENTNTAIInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LTENTNTAIInformation) WithoutReplay() LTENTNTAIInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LTENTNTAIInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LastVisitedGERANCellInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedGERANCellInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LastVisitedGERANCellInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LastVisitedGERANCellInformation) WithoutReplay() LastVisitedGERANCellInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LastVisitedGERANCellInformation
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ListeningSubframePattern) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ListeningSubframePattern", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ListeningSubframePattern", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ListeningSubframePattern) WithoutReplay() ListeningSubframePattern {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ListeningSubframePattern
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AdditionalGUTI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AdditionalGUTI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AdditionalGUTI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AdditionalGUTI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AdditionalGUTI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AdditionalGUTI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AdditionalGUTI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABLevelQoSParameters) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABLevelQoSParameters) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABLevelQoSParameters.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABLevelQoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABLevelQoSParameters) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABLevelQoSParameters.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABLevelQoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ExpectedUEActivityBehaviour) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ExpectedUEActivityBehaviour) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ExpectedUEActivityBehaviour.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ExpectedUEActivityBehaviour.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ExpectedUEActivityBehaviour) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ExpectedUEActivityBehaviour.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ExpectedUEActivityBehaviour.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ExpectedUEBehaviour) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ExpectedUEBehaviour) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ExpectedUEBehaviour.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ExpectedUEBehaviour.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ExpectedUEBehaviour) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ExpectedUEBehaviour.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ExpectedUEBehaviour.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *FiveGSTAI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *FiveGSTAI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("FiveGSTAI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("FiveGSTAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *FiveGSTAI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("FiveGSTAI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("FiveGSTAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ForbiddenLAsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ForbiddenLAsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ForbiddenLAsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenLAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ForbiddenLAsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ForbiddenLAsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenLAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ForbiddenTAsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ForbiddenTAsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ForbiddenTAsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ForbiddenTAsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ForbiddenTAsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenTAsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GBRQosInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GBRQosInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GBRQosInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GBRQosInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GBRQosInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GBRQosInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GBRQosInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GERANCellID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GERANCellID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GERANCellID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GERANCellID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GERANCellID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GERANCellID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GERANCellID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GNB) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GNB) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GNB.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GNB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GNB) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GNB.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GNB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GUMMEI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GUMMEI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GUMMEI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GUMMEI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GUMMEI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GUMMEI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GUMMEI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GlobalENBID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GlobalENBID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalENBID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalENBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GlobalENBID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalENBID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalENBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GlobalEnGNBID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GlobalEnGNBID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalEnGNBID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalEnGNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GlobalEnGNBID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalEnGNBID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalEnGNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *GlobalGNBID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *GlobalGNBID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalGNBID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalGNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *GlobalGNBID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("GlobalGNBID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("GlobalGNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LAI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LAI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LAI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LAI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LAI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LAI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LTENTNTAIInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LTENTNTAIInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LTENTNTAIInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LTENTNTAIInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LTENTNTAIInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LTENTNTAIInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LTENTNTAIInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ListeningSubframePattern) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ListeningSubframePattern) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ListeningSubframePattern.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ListeningSubframePattern.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ListeningSubframePattern) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ListeningSubframePattern.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ListeningSubframePattern.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AdditionalGUTI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AdditionalGUTI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AdditionalGUTI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AdditionalGUTI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAdditionalGUTI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AdditionalGUTI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AdditionalGUTI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AdditionalGUTI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AdditionalGUTI")
}
func (v *AdditionalGUTI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AdditionalGUTI")
}
func (v *AdditionalGUTI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAdditionalGUTI(v, &s)
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
func (v *AdditionalGUTI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AdditionalGUTI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABLevelQoSParameters) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABLevelQoSParameters")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABLevelQoSParameters) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABLevelQoSParameters")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABLevelQoSParameters(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABLevelQoSParameters")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABLevelQoSParameters")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABLevelQoSParameters) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABLevelQoSParameters")
}
func (v *ERABLevelQoSParameters) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABLevelQoSParameters")
}
func (v *ERABLevelQoSParameters) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABLevelQoSParameters(v, &s)
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
func (v *ERABLevelQoSParameters) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABLevelQoSParameters) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ExpectedUEActivityBehaviour) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ExpectedUEActivityBehaviour")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ExpectedUEActivityBehaviour) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ExpectedUEActivityBehaviour")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APExpectedUEActivityBehaviour(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ExpectedUEActivityBehaviour")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ExpectedUEActivityBehaviour")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ExpectedUEActivityBehaviour) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ExpectedUEActivityBehaviour")
}
func (v *ExpectedUEActivityBehaviour) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ExpectedUEActivityBehaviour")
}
func (v *ExpectedUEActivityBehaviour) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APExpectedUEActivityBehaviour(v, &s)
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
func (v *ExpectedUEActivityBehaviour) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ExpectedUEActivityBehaviour) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ExpectedUEBehaviour) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ExpectedUEBehaviour")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ExpectedUEBehaviour) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ExpectedUEBehaviour")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APExpectedUEBehaviour(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ExpectedUEBehaviour")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ExpectedUEBehaviour")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ExpectedUEBehaviour) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ExpectedUEBehaviour")
}
func (v *ExpectedUEBehaviour) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ExpectedUEBehaviour")
}
func (v *ExpectedUEBehaviour) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APExpectedUEBehaviour(v, &s)
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
func (v *ExpectedUEBehaviour) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ExpectedUEBehaviour) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *FiveGSTAI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "FiveGSTAI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *FiveGSTAI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "FiveGSTAI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APFiveGSTAI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "FiveGSTAI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "FiveGSTAI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *FiveGSTAI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "FiveGSTAI")
}
func (v *FiveGSTAI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "FiveGSTAI")
}
func (v *FiveGSTAI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APFiveGSTAI(v, &s)
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
func (v *FiveGSTAI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *FiveGSTAI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ForbiddenLAsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenLAsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenLAsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLAsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenLAsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenLAsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenLAsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenLAsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenLAsItem")
}
func (v *ForbiddenLAsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenLAsItem")
}
func (v *ForbiddenLAsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenLAsItem(v, &s)
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
func (v *ForbiddenLAsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenLAsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ForbiddenTAsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ForbiddenTAsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ForbiddenTAsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTAsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APForbiddenTAsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ForbiddenTAsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ForbiddenTAsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ForbiddenTAsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ForbiddenTAsItem")
}
func (v *ForbiddenTAsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ForbiddenTAsItem")
}
func (v *ForbiddenTAsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APForbiddenTAsItem(v, &s)
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
func (v *ForbiddenTAsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ForbiddenTAsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GBRQosInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GBRQosInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GBRQosInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GBRQosInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGBRQosInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GBRQosInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GBRQosInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GBRQosInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GBRQosInformation")
}
func (v *GBRQosInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GBRQosInformation")
}
func (v *GBRQosInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGBRQosInformation(v, &s)
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
func (v *GBRQosInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GBRQosInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GERANCellID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GERANCellID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GERANCellID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GERANCellID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGERANCellID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GERANCellID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GERANCellID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GERANCellID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GERANCellID")
}
func (v *GERANCellID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GERANCellID")
}
func (v *GERANCellID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGERANCellID(v, &s)
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
func (v *GERANCellID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GERANCellID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GNB) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GNB")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GNB) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GNB")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGNB(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GNB")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GNB")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GNB) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GNB")
}
func (v *GNB) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GNB")
}
func (v *GNB) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGNB(v, &s)
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
func (v *GNB) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GNB) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GNBIdentity) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GNBIdentity")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GNBIdentity) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GNBIdentity")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGNBIdentity(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GNBIdentity")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GNBIdentity")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GNBIdentity) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GNBIdentity")
}
func (v *GNBIdentity) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GNBIdentity")
}
func (v *GNBIdentity) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGNBIdentity(v, &s)
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
func (v *GNBIdentity) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GNBIdentity) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GUMMEI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GUMMEI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GUMMEI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GUMMEI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGUMMEI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GUMMEI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GUMMEI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GUMMEI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GUMMEI")
}
func (v *GUMMEI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GUMMEI")
}
func (v *GUMMEI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGUMMEI(v, &s)
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
func (v *GUMMEI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GUMMEI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GlobalENBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GlobalENBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GlobalENBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GlobalENBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGlobalENBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GlobalENBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GlobalENBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GlobalENBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GlobalENBID")
}
func (v *GlobalENBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GlobalENBID")
}
func (v *GlobalENBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGlobalENBID(v, &s)
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
func (v *GlobalENBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GlobalENBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GlobalEnGNBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GlobalEnGNBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GlobalEnGNBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GlobalEnGNBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGlobalEnGNBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GlobalEnGNBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GlobalEnGNBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GlobalEnGNBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GlobalEnGNBID")
}
func (v *GlobalEnGNBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GlobalEnGNBID")
}
func (v *GlobalEnGNBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGlobalEnGNBID(v, &s)
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
func (v *GlobalEnGNBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GlobalEnGNBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GlobalGNBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GlobalGNBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GlobalGNBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GlobalGNBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGlobalGNBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GlobalGNBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GlobalGNBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GlobalGNBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GlobalGNBID")
}
func (v *GlobalGNBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GlobalGNBID")
}
func (v *GlobalGNBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGlobalGNBID(v, &s)
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
func (v *GlobalGNBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GlobalGNBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InterSystemMeasurementItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InterSystemMeasurementItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InterSystemMeasurementItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInterSystemMeasurementItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InterSystemMeasurementItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InterSystemMeasurementItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InterSystemMeasurementItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InterSystemMeasurementItem")
}
func (v *InterSystemMeasurementItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InterSystemMeasurementItem")
}
func (v *InterSystemMeasurementItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInterSystemMeasurementItem(v, &s)
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
func (v *InterSystemMeasurementItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InterSystemMeasurementItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LAI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LAI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LAI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LAI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLAI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LAI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LAI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LAI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LAI")
}
func (v *LAI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LAI")
}
func (v *LAI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLAI(v, &s)
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
func (v *LAI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LAI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LTENTNTAIInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LTENTNTAIInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LTENTNTAIInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LTENTNTAIInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLTENTNTAIInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LTENTNTAIInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LTENTNTAIInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LTENTNTAIInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LTENTNTAIInformation")
}
func (v *LTENTNTAIInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LTENTNTAIInformation")
}
func (v *LTENTNTAIInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLTENTNTAIInformation(v, &s)
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
func (v *LTENTNTAIInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LTENTNTAIInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LastVisitedGERANCellInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LastVisitedGERANCellInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LastVisitedGERANCellInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LastVisitedGERANCellInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLastVisitedGERANCellInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LastVisitedGERANCellInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LastVisitedGERANCellInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LastVisitedGERANCellInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LastVisitedGERANCellInformation")
}
func (v *LastVisitedGERANCellInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LastVisitedGERANCellInformation")
}
func (v *LastVisitedGERANCellInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLastVisitedGERANCellInformation(v, &s)
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
func (v *LastVisitedGERANCellInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LastVisitedGERANCellInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ListeningSubframePattern) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ListeningSubframePattern")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ListeningSubframePattern) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ListeningSubframePattern")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APListeningSubframePattern(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ListeningSubframePattern")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ListeningSubframePattern")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ListeningSubframePattern) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ListeningSubframePattern")
}
func (v *ListeningSubframePattern) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ListeningSubframePattern")
}
func (v *ListeningSubframePattern) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APListeningSubframePattern(v, &s)
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
func (v *ListeningSubframePattern) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ListeningSubframePattern) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AdditionalGUTI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AdditionalGUTI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AdditionalGUTI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAdditionalGUTI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AdditionalGUTI{}
		return report, aper.OperationError(err, "AdditionalGUTI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AdditionalGUTI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABLevelQoSParameters) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABLevelQoSParameters")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABLevelQoSParameters
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABLevelQoSParameters(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABLevelQoSParameters{}
		return report, aper.OperationError(err, "ERABLevelQoSParameters")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABLevelQoSParameters")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ExpectedUEActivityBehaviour) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ExpectedUEActivityBehaviour")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ExpectedUEActivityBehaviour
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APExpectedUEActivityBehaviour(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ExpectedUEActivityBehaviour{}
		return report, aper.OperationError(err, "ExpectedUEActivityBehaviour")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ExpectedUEActivityBehaviour")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ExpectedUEBehaviour) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ExpectedUEBehaviour")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ExpectedUEBehaviour
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APExpectedUEBehaviour(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ExpectedUEBehaviour{}
		return report, aper.OperationError(err, "ExpectedUEBehaviour")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ExpectedUEBehaviour")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *FiveGSTAI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "FiveGSTAI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded FiveGSTAI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APFiveGSTAI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = FiveGSTAI{}
		return report, aper.OperationError(err, "FiveGSTAI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "FiveGSTAI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenLAsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenLAsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenLAsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenLAsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenLAsItem{}
		return report, aper.OperationError(err, "ForbiddenLAsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenLAsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ForbiddenTAsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ForbiddenTAsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ForbiddenTAsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APForbiddenTAsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ForbiddenTAsItem{}
		return report, aper.OperationError(err, "ForbiddenTAsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ForbiddenTAsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GBRQosInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GBRQosInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GBRQosInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGBRQosInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GBRQosInformation{}
		return report, aper.OperationError(err, "GBRQosInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GBRQosInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GERANCellID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GERANCellID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GERANCellID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGERANCellID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GERANCellID{}
		return report, aper.OperationError(err, "GERANCellID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GERANCellID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GNB) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GNB")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GNB
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGNB(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GNB{}
		return report, aper.OperationError(err, "GNB")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GNB")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GNBIdentity) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GNBIdentity")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GNBIdentity
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGNBIdentity(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GNBIdentity{}
		return report, aper.OperationError(err, "GNBIdentity")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GNBIdentity")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GUMMEI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GUMMEI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GUMMEI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGUMMEI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GUMMEI{}
		return report, aper.OperationError(err, "GUMMEI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GUMMEI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GlobalENBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GlobalENBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GlobalENBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGlobalENBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GlobalENBID{}
		return report, aper.OperationError(err, "GlobalENBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GlobalENBID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GlobalEnGNBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GlobalEnGNBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GlobalEnGNBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGlobalEnGNBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GlobalEnGNBID{}
		return report, aper.OperationError(err, "GlobalEnGNBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GlobalEnGNBID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GlobalGNBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GlobalGNBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GlobalGNBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGlobalGNBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GlobalGNBID{}
		return report, aper.OperationError(err, "GlobalGNBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GlobalGNBID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InterSystemMeasurementItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InterSystemMeasurementItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInterSystemMeasurementItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InterSystemMeasurementItem{}
		return report, aper.OperationError(err, "InterSystemMeasurementItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterSystemMeasurementItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LAI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LAI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LAI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLAI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LAI{}
		return report, aper.OperationError(err, "LAI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LAI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LTENTNTAIInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LTENTNTAIInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LTENTNTAIInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLTENTNTAIInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LTENTNTAIInformation{}
		return report, aper.OperationError(err, "LTENTNTAIInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LTENTNTAIInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LastVisitedGERANCellInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LastVisitedGERANCellInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LastVisitedGERANCellInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLastVisitedGERANCellInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LastVisitedGERANCellInformation{}
		return report, aper.OperationError(err, "LastVisitedGERANCellInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LastVisitedGERANCellInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ListeningSubframePattern) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ListeningSubframePattern")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ListeningSubframePattern
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APListeningSubframePattern(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ListeningSubframePattern{}
		return report, aper.OperationError(err, "ListeningSubframePattern")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ListeningSubframePattern")
}

// HandoverSuccess represents the ASN.1 type HandoverSuccess (SEQUENCE).
type HandoverSuccess struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s09.HandoverSuccessIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes HandoverSuccess to APER format.
func (v *HandoverSuccess) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverSuccess) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s09.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes HandoverSuccess from APER format.
func (v *HandoverSuccess) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverSuccess with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverSuccess) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverSuccess")
	}
	bb.EnterComponent("HandoverSuccess")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverSuccess")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverSuccess")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverSuccess")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverSuccess) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverSuccess{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s09.HandoverSuccessIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s09.HandoverSuccessIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s09.BridgeHandoverSuccessIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
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
	bb.LeaveComponent(toleranceMark_protocolies)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverSuccess) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverSuccess", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverSuccess", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverSuccess) WithoutReplay() HandoverSuccess {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverSuccess
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverSuccess) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverSuccess) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverSuccess.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverSuccess.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverSuccess) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverSuccess.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverSuccess.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverSuccess) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverSuccess")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverSuccess) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverSuccess")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverSuccess(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverSuccess")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverSuccess")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverSuccess) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverSuccess")
}
func (v *HandoverSuccess) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverSuccess")
}
func (v *HandoverSuccess) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverSuccess(v, &s)
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
func (v *HandoverSuccess) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverSuccess) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverSuccess) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverSuccess")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverSuccess
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverSuccess(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverSuccess{}
		return report, aper.OperationError(err, "HandoverSuccess")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverSuccess")
}

// IRATCellID represents the ASN.1 CHOICE type IRAT-Cell-ID.
type IRATCellID struct {
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
	EUTRAN             []byte                `json:"EUTRAN,omitzero"`
	UTRAN              []byte                `json:"UTRAN,omitzero"`
	GERAN              []byte                `json:"GERAN,omitzero"`
	EHRPD              *s00.EHRPDSectorID    `json:"EHRPD,omitempty"`
}

// EventTriggeredCellLoadReportingRequest represents the ASN.1 type EventTriggeredCellLoadReportingRequest (SEQUENCE).
type EventTriggeredCellLoadReportingRequest struct {
	replay                             aper.Snapshot
	stream                             aper.WireSpan
	received                           bool
	withoutReplay                      bool
	receivedAbsolute                   bool
	receivedBytes                      aper.WireSpan
	receivedLocation                   aper.Location
	NumberOfMeasurementReportingLevels s00.NumberOfMeasurementReportingLevels `asn1:"tag:0,context,implicit"`
	extCount                           int64                                  `asn1:"-" json:"-"`
	extPresent                         []bool                                 `asn1:"-" json:"-"`
	extData                            [][]byte                               `asn1:"-" json:"-"`
	perPadding                         aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding                      []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin                          []aper.OpaqueOrigin
	extWire                            []aper.WireSpan
}

// EventTriggeredCellLoadReportingResponse represents the ASN.1 type EventTriggeredCellLoadReportingResponse (SEQUENCE).
type EventTriggeredCellLoadReportingResponse struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	CellLoadReportingResponse s17.CellLoadReportingResponse `asn1:"tag:0,context,explicit"`
	OverloadFlag              *s00.OverloadFlag             `asn1:"tag:1,context,implicit,optional" json:"OverloadFlag,omitempty"`
	extCount                  int64                         `asn1:"-" json:"-"`
	extPresent                []bool                        `asn1:"-" json:"-"`
	extData                   [][]byte                      `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}
type CandidateCellList = []IRATCellID

// MarshalAPER encodes IRATCellID to APER format.
func (v *IRATCellID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *IRATCellID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "IRATCellID:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "IRATCellID:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "IRATCellID:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "IRATCellID:", v.Choice)
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
		case s00.IRATCellIDChoiceEHRPD:
			if v.EHRPD == nil {
				return fmt.Errorf("choice alternative eHRPD is nil")
			}
			if err := aper.EncodeOctetStringAligned(inner, []byte(*v.EHRPD), 16, 16, true); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown IRATCellID extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s07.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
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
	case s00.IRATCellIDChoiceEUTRAN:
		if err := aper.EncodeOctetStringAligned(bb, v.EUTRAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding eUTRAN: %w", err)
		}
	case s00.IRATCellIDChoiceUTRAN:
		if err := aper.EncodeOctetStringAligned(bb, v.UTRAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRAN: %w", err)
		}
	case s00.IRATCellIDChoiceGERAN:
		if err := aper.EncodeOctetStringAligned(bb, v.GERAN, 0, 0, false); err != nil {
			return fmt.Errorf("encoding gERAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown IRATCellID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes IRATCellID from APER format.
func (v *IRATCellID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes IRATCellID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *IRATCellID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	bb.EnterComponent("IRATCellID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	padding, err := aper.CaptureFinalBits(bb, "IRATCellID")
	if err != nil {
		return runtime.WrapDecodePath(err, "IRATCellID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *IRATCellID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = IRATCellID{}
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
		case s00.IRATCellIDChoiceEHRPD:
			extensionPath = "EHRPD"
			val_ehrpd, err := aper.DecodeOctetStringAligned(inner, 16, 16, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			tmp_ehrpd := s00.EHRPDSectorID(val_ehrpd)
			if err := aper.ChargeValue(inner, tmp_ehrpd); err != nil {
				return err
			}
			v.EHRPD = &tmp_ehrpd
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
	case s00.IRATCellIDChoiceEUTRAN:
		val_eutran, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "EUTRAN")
		}
		tmp_eutran := val_eutran
		v.EUTRAN = tmp_eutran
	case s00.IRATCellIDChoiceUTRAN:
		val_utran, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRAN")
		}
		tmp_utran := val_utran
		v.UTRAN = tmp_utran
	case s00.IRATCellIDChoiceGERAN:
		val_geran, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "GERAN")
		}
		tmp_geran := val_geran
		v.GERAN = tmp_geran
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes EventTriggeredCellLoadReportingRequest to APER format.
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.NumberOfMeasurementReportingLevels), 5, true); err != nil {
		return fmt.Errorf("encoding numberOfMeasurementReportingLevels: %w", err)
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

// UnmarshalAPER decodes EventTriggeredCellLoadReportingRequest from APER format.
func (v *EventTriggeredCellLoadReportingRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EventTriggeredCellLoadReportingRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EventTriggeredCellLoadReportingRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	bb.EnterComponent("EventTriggeredCellLoadReportingRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "EventTriggeredCellLoadReportingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EventTriggeredCellLoadReportingRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventTriggeredCellLoadReportingRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofmeasurementreportinglevels, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfMeasurementReportingLevels"})
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfMeasurementReportingLevels")
	}
	v.NumberOfMeasurementReportingLevels = s00.NumberOfMeasurementReportingLevels(val_numberofmeasurementreportinglevels)
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

// MarshalAPER encodes EventTriggeredCellLoadReportingResponse to APER format.
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.OverloadFlag != nil); err != nil {
		return err
	}
	if err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERTo(&v.CellLoadReportingResponse, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cellLoadReportingResponse: %w", err)
	}
	if v.OverloadFlag != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.OverloadFlag), 1, true); err != nil {
			return fmt.Errorf("encoding overloadFlag: %w", err)
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

// UnmarshalAPER decodes EventTriggeredCellLoadReportingResponse from APER format.
func (v *EventTriggeredCellLoadReportingResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EventTriggeredCellLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EventTriggeredCellLoadReportingResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	bb.EnterComponent("EventTriggeredCellLoadReportingResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "EventTriggeredCellLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReportingResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EventTriggeredCellLoadReportingResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventTriggeredCellLoadReportingResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_overloadflag, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellloadreportingresponse := bb.EnterComponent("CellLoadReportingResponse")
	if err := s17.BridgeCellLoadReportingResponseMethodUnmarshalAPERFrom(&v.CellLoadReportingResponse, bb); err != nil {
		return runtime.WrapDecodePath(err, "CellLoadReportingResponse")
	}
	bb.LeaveComponent(toleranceMark_cellloadreportingresponse)
	if opt_overloadflag {
		val_overloadflag, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OverloadFlag"})
		if err != nil {
			return runtime.WrapDecodePath(err, "OverloadFlag")
		}
		tmp_overloadflag := s00.OverloadFlag(val_overloadflag)
		if err := aper.ChargeValue(bb, tmp_overloadflag); err != nil {
			return err
		}
		v.OverloadFlag = (*s00.OverloadFlag)(bb.OwnInt64(int64(tmp_overloadflag)))

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
func (v *EventTriggeredCellLoadReportingRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventTriggeredCellLoadReportingRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EventTriggeredCellLoadReportingRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EventTriggeredCellLoadReportingRequest) WithoutReplay() EventTriggeredCellLoadReportingRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EventTriggeredCellLoadReportingRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EventTriggeredCellLoadReportingResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventTriggeredCellLoadReportingResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EventTriggeredCellLoadReportingResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EventTriggeredCellLoadReportingResponse) WithoutReplay() EventTriggeredCellLoadReportingResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EventTriggeredCellLoadReportingResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *IRATCellID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "IRATCellID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "IRATCellID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v IRATCellID) WithoutReplay() IRATCellID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero IRATCellID
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *EventTriggeredCellLoadReportingRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EventTriggeredCellLoadReportingRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventTriggeredCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventTriggeredCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EventTriggeredCellLoadReportingRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventTriggeredCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventTriggeredCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EventTriggeredCellLoadReportingResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EventTriggeredCellLoadReportingResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventTriggeredCellLoadReportingResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventTriggeredCellLoadReportingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EventTriggeredCellLoadReportingResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventTriggeredCellLoadReportingResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventTriggeredCellLoadReportingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EventTriggeredCellLoadReportingRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EventTriggeredCellLoadReportingRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EventTriggeredCellLoadReportingRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEventTriggeredCellLoadReportingRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EventTriggeredCellLoadReportingRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EventTriggeredCellLoadReportingRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EventTriggeredCellLoadReportingRequest")
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EventTriggeredCellLoadReportingRequest")
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEventTriggeredCellLoadReportingRequest(v, &s)
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
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EventTriggeredCellLoadReportingRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EventTriggeredCellLoadReportingResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EventTriggeredCellLoadReportingResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EventTriggeredCellLoadReportingResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEventTriggeredCellLoadReportingResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EventTriggeredCellLoadReportingResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EventTriggeredCellLoadReportingResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EventTriggeredCellLoadReportingResponse")
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EventTriggeredCellLoadReportingResponse")
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEventTriggeredCellLoadReportingResponse(v, &s)
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
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EventTriggeredCellLoadReportingResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *IRATCellID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "IRATCellID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *IRATCellID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "IRATCellID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APIRATCellID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "IRATCellID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "IRATCellID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *IRATCellID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "IRATCellID")
}
func (v *IRATCellID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "IRATCellID")
}
func (v *IRATCellID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APIRATCellID(v, &s)
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
func (v *IRATCellID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *IRATCellID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EventTriggeredCellLoadReportingRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EventTriggeredCellLoadReportingRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EventTriggeredCellLoadReportingRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEventTriggeredCellLoadReportingRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EventTriggeredCellLoadReportingRequest{}
		return report, aper.OperationError(err, "EventTriggeredCellLoadReportingRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EventTriggeredCellLoadReportingRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EventTriggeredCellLoadReportingResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EventTriggeredCellLoadReportingResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EventTriggeredCellLoadReportingResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEventTriggeredCellLoadReportingResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EventTriggeredCellLoadReportingResponse{}
		return report, aper.OperationError(err, "EventTriggeredCellLoadReportingResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EventTriggeredCellLoadReportingResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *IRATCellID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "IRATCellID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded IRATCellID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APIRATCellID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = IRATCellID{}
		return report, aper.OperationError(err, "IRATCellID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "IRATCellID")
}

type HandoverCancelIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowCause       *s14.Cause
}

func (v HandoverCancelIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverCancelIEValue and reports whether the opaque alternative is selected.
func (v *HandoverCancelIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverCancelIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelIEs"}}
}
func (HandoverCancelIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverCancelIEValue and reports whether that alternative is active.
func (v *HandoverCancelIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverCancelIEValue and reports whether that alternative is active.
func (v *HandoverCancelIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCause returns the selected Cause value of HandoverCancelIEValue and reports whether that alternative is active.
func (v *HandoverCancelIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v HandoverCancelIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverCancelIEValue, error) {
	out := HandoverCancelIEValue{id: id}
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v HandoverCancelIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverCancelIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverCancelIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverCancelIEValue:", v.id)
	}
}

type LocationReportingFailureIndicationIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowCause       *s14.Cause
}

func (v LocationReportingFailureIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	}
	return false
}

// Opaque returns the retained opaque open value of LocationReportingFailureIndicationIEValue and reports whether the opaque alternative is selected.
func (v *LocationReportingFailureIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (LocationReportingFailureIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingFailureIndicationIEs"}}
}
func (LocationReportingFailureIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of LocationReportingFailureIndicationIEValue and reports whether that alternative is active.
func (v *LocationReportingFailureIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of LocationReportingFailureIndicationIEValue and reports whether that alternative is active.
func (v *LocationReportingFailureIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsCause returns the selected Cause value of LocationReportingFailureIndicationIEValue and reports whether that alternative is active.
func (v *LocationReportingFailureIndicationIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v LocationReportingFailureIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (LocationReportingFailureIndicationIEValue, error) {
	out := LocationReportingFailureIndicationIEValue{id: id}
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v LocationReportingFailureIndicationIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v LocationReportingFailureIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "LocationReportingFailureIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportingFailureIndicationIEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "LocationReportingFailureIndicationIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "LocationReportingFailureIndicationIEValue:", v.id)
	}
}

type HandoverCancelIETable struct{}

func HandoverCancelIEs() HandoverCancelIETable { return HandoverCancelIETable{} }

// ID returns the ASN.1 object-set identity of HandoverCancelIETable.
func (HandoverCancelIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverCancelIETable.
func (HandoverCancelIETable) Table() s00.HandoverCancelIEValueIETable {
	return func() s00.HandoverCancelIEValueIETable {
		sealed := s00.HandoverCancelIEValueIETable{}
		*s00.BridgeHandoverCancelIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverCancelIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverCancelIETable.
func (t HandoverCancelIETable) MMEUES1APID() HandoverCancelMMEUES1APIDIEBinding {
	return HandoverCancelMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverCancelIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverCancelIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverCancelIEValue {
			return HandoverCancelIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverCancelIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverCancelIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverCancelIETable.
func (t HandoverCancelIETable) ENBUES1APID() HandoverCancelENBUES1APIDIEBinding {
	return HandoverCancelENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverCancelIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverCancelIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverCancelIEValue {
			return HandoverCancelIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverCancelIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverCancelIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverCancelIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverCancelIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of HandoverCancelIETable.
func (t HandoverCancelIETable) Cause() HandoverCancelCauseIEBinding {
	return HandoverCancelCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero HandoverCancelIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding HandoverCancelIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverCancelIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) HandoverCancelIEValue {
			return HandoverCancelIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverCancelIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverCancelIETable.
func (t HandoverCancelIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverCancelIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return HandoverCancelIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverCancelIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverCancelIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverCancelIEField{Id: id, Criticality: criticality, Value: HandoverCancelIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// EUTRANResponseCodec binds the complete source value type.
func EUTRANResponseCodec() s17.EUTRANResponseValueCodec {
	return func() s17.EUTRANResponseValueCodec {
		sealed := s17.EUTRANResponseValueCodec{}
		*s17.BridgeEUTRANResponseValueCodecFieldPath(&sealed) = "EUTRANResponse"
		*s17.BridgeEUTRANResponseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANResponse, error) {
			var value s17.EUTRANResponse
			if err := s17.BridgeEUTRANResponseMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
				return s17.EUTRANResponse{}, err
			}
			*s17.BridgeEUTRANResponseFieldReceived(&value) = true
			*s17.BridgeEUTRANResponseFieldReceivedAbsolute(&value) = true
			*s17.BridgeEUTRANResponseFieldReceivedBytes(&value) = aper.OriginalWire(data)
			return value, nil
		}
		*s17.BridgeEUTRANResponseValueCodecFieldEncode(&sealed) = func(value s17.EUTRANResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s17.BridgeEUTRANResponseMethodMarshalAPERBudget((&value), budget, fresh)
		}
		*s17.BridgeEUTRANResponseValueCodecFieldCapture(&sealed) = func(v s17.EUTRANResponse, options aper.DecodeState) (s17.EUTRANResponse, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APEUTRANResponse(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeEUTRANResponseValueCodecFieldCompare(&sealed) = func(v s17.EUTRANResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APEUTRANResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeEUTRANResponseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANResponse"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EUTRANcellLoadReportingResponseCodec binds the complete source value type.
func EUTRANcellLoadReportingResponseCodec() EUTRANcellLoadReportingResponseValueCodec {
	return EUTRANcellLoadReportingResponseValueCodec{path: "EUTRANcellLoadReportingResponse", decode: func(data []byte, options aper.DecodeState) (s17.EUTRANcellLoadReportingResponse, error) {
		var value s17.EUTRANcellLoadReportingResponse
		if err := s17.BridgeEUTRANcellLoadReportingResponseMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s17.EUTRANcellLoadReportingResponse{}, err
		}
		*s17.BridgeEUTRANcellLoadReportingResponseFieldReceived(&value) = true
		*s17.BridgeEUTRANcellLoadReportingResponseFieldReceivedAbsolute(&value) = true
		*s17.BridgeEUTRANcellLoadReportingResponseFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s17.EUTRANcellLoadReportingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s17.BridgeEUTRANcellLoadReportingResponseMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s17.EUTRANcellLoadReportingResponse, options aper.DecodeState) (s17.EUTRANcellLoadReportingResponse, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s17.BridgeCaptureS1APEUTRANcellLoadReportingResponse(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s17.EUTRANcellLoadReportingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s17.BridgeCompareS1APEUTRANcellLoadReportingResponse(&v, &s)

		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANcellLoadReportingResponse"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EventTriggeredCellLoadReportingRequestCodec binds the complete source value type.
func EventTriggeredCellLoadReportingRequestCodec() EventTriggeredCellLoadReportingRequestValueCodec {
	return EventTriggeredCellLoadReportingRequestValueCodec{path: "EventTriggeredCellLoadReportingRequest", decode: func(data []byte, options aper.DecodeState) (EventTriggeredCellLoadReportingRequest, error) {
		var value EventTriggeredCellLoadReportingRequest
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EventTriggeredCellLoadReportingRequest{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EventTriggeredCellLoadReportingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EventTriggeredCellLoadReportingRequest, options aper.DecodeState) (EventTriggeredCellLoadReportingRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEventTriggeredCellLoadReportingRequest(
			&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EventTriggeredCellLoadReportingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEventTriggeredCellLoadReportingRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EventTriggeredCellLoadReportingRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EventTriggeredCellLoadReportingResponseCodec binds the complete source value type.
func EventTriggeredCellLoadReportingResponseCodec() EventTriggeredCellLoadReportingResponseValueCodec {
	return EventTriggeredCellLoadReportingResponseValueCodec{path: "EventTriggeredCellLoadReportingResponse", decode: func(data []byte, options aper.DecodeState) (EventTriggeredCellLoadReportingResponse, error) {
		var value EventTriggeredCellLoadReportingResponse
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EventTriggeredCellLoadReportingResponse{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EventTriggeredCellLoadReportingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EventTriggeredCellLoadReportingResponse, options aper.DecodeState) (EventTriggeredCellLoadReportingResponse, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEventTriggeredCellLoadReportingResponse(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EventTriggeredCellLoadReportingResponse, root aper.Snapshot, budget aper.DecodeBudget,
	) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEventTriggeredCellLoadReportingResponse(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EventTriggeredCellLoadReportingResponse"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ExpectedUEActivityBehaviourCodec binds the complete source value type.
func ExpectedUEActivityBehaviourCodec() ExpectedUEActivityBehaviourValueCodec {
	return ExpectedUEActivityBehaviourValueCodec{path: "ExpectedUEActivityBehaviour", decode: func(data []byte, options aper.DecodeState) (ExpectedUEActivityBehaviour, error) {
		var value ExpectedUEActivityBehaviour
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ExpectedUEActivityBehaviour{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ExpectedUEActivityBehaviour, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ExpectedUEActivityBehaviour, options aper.DecodeState) (ExpectedUEActivityBehaviour, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APExpectedUEActivityBehaviour(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ExpectedUEActivityBehaviour, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APExpectedUEActivityBehaviour(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedUEActivityBehaviour"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// FiveGSTAICodec binds the complete source value type.
func FiveGSTAICodec() FiveGSTAIValueCodec {
	return FiveGSTAIValueCodec{path: "FiveGSTAI", decode: func(data []byte, options aper.DecodeState) (FiveGSTAI, error) {
		var value FiveGSTAI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return FiveGSTAI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value FiveGSTAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v FiveGSTAI, options aper.DecodeState) (FiveGSTAI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		BridgeCaptureS1APFiveGSTAI(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v FiveGSTAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APFiveGSTAI(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FiveGSTAI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ForbiddenLAsItemCodec binds the complete source value type.
func ForbiddenLAsItemCodec() ForbiddenLAsItemValueCodec {
	return ForbiddenLAsItemValueCodec{path: "ForbiddenLAsItem", decode: func(data []byte, options aper.DecodeState) (ForbiddenLAsItem, error) {
		var value ForbiddenLAsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ForbiddenLAsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ForbiddenLAsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ForbiddenLAsItem, options aper.DecodeState) (ForbiddenLAsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APForbiddenLAsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ForbiddenLAsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APForbiddenLAsItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenLAsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ForbiddenTAsItemCodec binds the complete source value type.
func ForbiddenTAsItemCodec() ForbiddenTAsItemValueCodec {
	return ForbiddenTAsItemValueCodec{path: "ForbiddenTAsItem", decode: func(data []byte, options aper.DecodeState) (ForbiddenTAsItem, error) {
		var value ForbiddenTAsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ForbiddenTAsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ForbiddenTAsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ForbiddenTAsItem, options aper.DecodeState) (ForbiddenTAsItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APForbiddenTAsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ForbiddenTAsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APForbiddenTAsItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenTAsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GBRQosInformationCodec binds the complete source value type.
func GBRQosInformationCodec() GBRQosInformationValueCodec {
	return GBRQosInformationValueCodec{path: "GBRQosInformation", decode: func(data []byte, options aper.DecodeState) (GBRQosInformation, error) {
		var value GBRQosInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GBRQosInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GBRQosInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GBRQosInformation, options aper.DecodeState) (GBRQosInformation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGBRQosInformation(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v GBRQosInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGBRQosInformation(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GBRQosInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GERANCellIDCodec binds the complete source value type.
func GERANCellIDCodec() GERANCellIDValueCodec {
	return GERANCellIDValueCodec{path: "GERANCellID", decode: func(data []byte, options aper.DecodeState) (GERANCellID, error) {
		var value GERANCellID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GERANCellID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GERANCellID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GERANCellID, options aper.DecodeState) (GERANCellID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGERANCellID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v GERANCellID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGERANCellID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GERANCellID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GNBCodec binds the complete source value type.
func GNBCodec() GNBValueCodec {
	return GNBValueCodec{path: "GNB", decode: func(data []byte, options aper.DecodeState) (GNB, error) {
		var value GNB
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GNB{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GNB, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GNB, options aper.DecodeState) (GNB, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGNB(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v GNB, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGNB(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GNB"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GNBIdentityCodec binds the complete source value type.
func GNBIdentityCodec() GNBIdentityValueCodec {
	return GNBIdentityValueCodec{path: "GNBIdentity", decode: func(data []byte, options aper.DecodeState) (GNBIdentity, error) {
		var value GNBIdentity
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GNBIdentity{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GNBIdentity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GNBIdentity, options aper.DecodeState) (GNBIdentity, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGNBIdentity(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v GNBIdentity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGNBIdentity(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GNBIdentity"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GlobalEnGNBIDCodec binds the complete source value type.
func GlobalEnGNBIDCodec() GlobalEnGNBIDValueCodec {
	return GlobalEnGNBIDValueCodec{path: "GlobalEnGNBID", decode: func(data []byte, options aper.DecodeState) (GlobalEnGNBID, error) {
		var value GlobalEnGNBID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GlobalEnGNBID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GlobalEnGNBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GlobalEnGNBID, options aper.DecodeState) (GlobalEnGNBID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGlobalEnGNBID(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v GlobalEnGNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGlobalEnGNBID(&v, &s)
		s.End(f, root, false)
		return s.Plan(),

			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalEnGNBID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// GlobalGNBIDCodec binds the complete source value type.
func GlobalGNBIDCodec() GlobalGNBIDValueCodec {
	return GlobalGNBIDValueCodec{path: "GlobalGNBID", decode: func(data []byte, options aper.DecodeState) (GlobalGNBID, error) {
		var value GlobalGNBID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return GlobalGNBID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value GlobalGNBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v GlobalGNBID, options aper.DecodeState) (GlobalGNBID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APGlobalGNBID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v GlobalGNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APGlobalGNBID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalGNBID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// IRATCellIDCodec binds the complete source value type.
func IRATCellIDCodec() IRATCellIDValueCodec {
	return IRATCellIDValueCodec{path: "IRATCellID", decode: func(data []byte, options aper.DecodeState) (IRATCellID, error) {
		var value IRATCellID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return IRATCellID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value IRATCellID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v IRATCellID, options aper.DecodeState) (IRATCellID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureS1APIRATCellID(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v IRATCellID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APIRATCellID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IRATCellID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// InterSystemMeasurementItemCodec binds the complete source value type.
func InterSystemMeasurementItemCodec() InterSystemMeasurementItemValueCodec {
	return InterSystemMeasurementItemValueCodec{path: "InterSystemMeasurementItem", decode: func(data []byte, options aper.DecodeState) (InterSystemMeasurementItem, error) {
		var value InterSystemMeasurementItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InterSystemMeasurementItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InterSystemMeasurementItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InterSystemMeasurementItem, options aper.DecodeState) (InterSystemMeasurementItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APInterSystemMeasurementItem(&v, &s)
		var root aper.Snapshot
		s.End(
			f, &root, false)
		return v, root
	}, compare: func(v InterSystemMeasurementItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APInterSystemMeasurementItem(&v, &s)
		s.End(f,
			root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemMeasurementItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LastVisitedGERANCellInformationCodec binds the complete source value type.
func LastVisitedGERANCellInformationCodec() LastVisitedGERANCellInformationValueCodec {
	return LastVisitedGERANCellInformationValueCodec{path: "LastVisitedGERANCellInformation", decode: func(data []byte, options aper.DecodeState) (LastVisitedGERANCellInformation, error) {
		var value LastVisitedGERANCellInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LastVisitedGERANCellInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LastVisitedGERANCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LastVisitedGERANCellInformation, options aper.DecodeState) (LastVisitedGERANCellInformation, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APLastVisitedGERANCellInformation(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v LastVisitedGERANCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APLastVisitedGERANCellInformation(&v, &s)

		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedGERANCellInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ListeningSubframePatternCodec binds the complete source value type.
func ListeningSubframePatternCodec() ListeningSubframePatternValueCodec {
	return ListeningSubframePatternValueCodec{path: "ListeningSubframePattern", decode: func(data []byte, options aper.DecodeState) (ListeningSubframePattern, error) {
		var value ListeningSubframePattern
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ListeningSubframePattern{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ListeningSubframePattern, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ListeningSubframePattern, options aper.DecodeState) (ListeningSubframePattern, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APListeningSubframePattern(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ListeningSubframePattern, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APListeningSubframePattern(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ListeningSubframePattern"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeAdditionalGUTIAPERValueFieldContext(v *AdditionalGUTIAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAdditionalGUTIAPERValueFieldReceived(v *AdditionalGUTIAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAdditionalGUTIAPERValueFieldReplay(v *AdditionalGUTIAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAdditionalGUTIAPERValueFieldWithoutReplay(v *AdditionalGUTIAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAdditionalGUTIFieldExtCount(v *AdditionalGUTI) *int64                { return &v.extCount }
func BridgeAdditionalGUTIFieldExtData(v *AdditionalGUTI) *[][]byte              { return &v.extData }
func BridgeAdditionalGUTIFieldExtOrigin(v *AdditionalGUTI) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeAdditionalGUTIFieldExtPresent(v *AdditionalGUTI) *[]bool             { return &v.extPresent }
func BridgeAdditionalGUTIFieldExtWire(v *AdditionalGUTI) *[]aper.WireSpan       { return &v.extWire }
func BridgeAdditionalGUTIFieldIEExtensionsIndef(v *AdditionalGUTI) *bool        { return &v.iEExtensionsIndef }
func BridgeAdditionalGUTIFieldPerExtPadding(v *AdditionalGUTI) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAdditionalGUTIFieldPerPadding(v *AdditionalGUTI) *aper.FinalPadding { return &v.perPadding }
func BridgeAdditionalGUTIFieldReceived(v *AdditionalGUTI) *bool                { return &v.received }
func BridgeAdditionalGUTIFieldReceivedAbsolute(v *AdditionalGUTI) *bool        { return &v.receivedAbsolute }
func BridgeAdditionalGUTIFieldReceivedBytes(v *AdditionalGUTI) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAdditionalGUTIFieldReceivedLocation(v *AdditionalGUTI) *aper.Location {
	return &v.receivedLocation
}
func BridgeAdditionalGUTIFieldReplay(v *AdditionalGUTI) *aper.Snapshot { return &v.replay }
func BridgeAdditionalGUTIFieldStream(v *AdditionalGUTI) *aper.WireSpan { return &v.stream }
func BridgeAdditionalGUTIFieldWithoutReplay(v *AdditionalGUTI) *bool   { return &v.withoutReplay }
func BridgeAdditionalGUTIMethodMarshalAPERBudget(v *AdditionalGUTI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAdditionalGUTIMethodMarshalAPERBudgetValue(v *AdditionalGUTI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeAdditionalGUTIMethodMarshalAPERChanged(v *AdditionalGUTI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAdditionalGUTIMethodMarshalAPERChangedValue(v *AdditionalGUTI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAdditionalGUTIMethodMarshalAPERLegacy(v *AdditionalGUTI) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAdditionalGUTIMethodMarshalAPERNewValue(v *AdditionalGUTI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeAdditionalGUTIMethodMarshalAPERPlanned(v *AdditionalGUTI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeAdditionalGUTIMethodMarshalAPERTo(v *AdditionalGUTI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAdditionalGUTIMethodUnmarshalAPERFrom(v *AdditionalGUTI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAdditionalGUTIMethodUnmarshalAPERLegacy(v *AdditionalGUTI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAdditionalGUTIMethodUnmarshalAPERWithOptions(v *AdditionalGUTI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAdditionalGUTIValueCodecFieldCapture(v *AdditionalGUTIValueCodec) *func(AdditionalGUTI, aper.DecodeState) (AdditionalGUTI, aper.Snapshot) {
	return &v.capture
}
func BridgeAdditionalGUTIValueCodecFieldCompare(v *AdditionalGUTIValueCodec) *func(AdditionalGUTI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeAdditionalGUTIValueCodecFieldContext(v *AdditionalGUTIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAdditionalGUTIValueCodecFieldDecode(v *AdditionalGUTIValueCodec) *func([]byte, aper.DecodeState) (AdditionalGUTI, error) {
	return &v.decode
}
func BridgeAdditionalGUTIValueCodecFieldEncode(v *AdditionalGUTIValueCodec) *func(AdditionalGUTI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAdditionalGUTIValueCodecFieldPath(v *AdditionalGUTIValueCodec) *aper.Path { return &v.path }
func BridgeAdditionalGUTIValueCodecMethodEncodeBudgetValue(v AdditionalGUTIValueCodec, a0 AdditionalGUTI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeAdditionalGUTIValueCodecMethodEncodeChanged(v AdditionalGUTIValueCodec, a0 AdditionalGUTI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCandidateCellListAPERValueFieldContext(v *CandidateCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidateCellListAPERValueFieldReceived(v *CandidateCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeCandidateCellListAPERValueFieldReplay(v *CandidateCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCandidateCellListAPERValueFieldWithoutReplay(v *CandidateCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCandidateCellListValueCodecFieldCapture(v *CandidateCellListValueCodec) *func(CandidateCellList, aper.DecodeState) (CandidateCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeCandidateCellListValueCodecFieldCompare(v *CandidateCellListValueCodec) *func(CandidateCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCandidateCellListValueCodecFieldContext(v *CandidateCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidateCellListValueCodecFieldDecode(v *CandidateCellListValueCodec) *func([]byte, aper.DecodeState) (CandidateCellList, error) {
	return &v.decode
}
func BridgeCandidateCellListValueCodecFieldEncode(v *CandidateCellListValueCodec) *func(CandidateCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCandidateCellListValueCodecFieldPath(v *CandidateCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCandidateCellListValueCodecMethodEncodeBudgetValue(v CandidateCellListValueCodec, a0 CandidateCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeCandidateCellListValueCodecMethodEncodeChanged(v CandidateCellListValueCodec, a0 CandidateCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABLevelQoSParametersAPERValueFieldContext(v *ERABLevelQoSParametersAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABLevelQoSParametersAPERValueFieldReceived(v *ERABLevelQoSParametersAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABLevelQoSParametersAPERValueFieldReplay(v *ERABLevelQoSParametersAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABLevelQoSParametersAPERValueFieldWithoutReplay(v *ERABLevelQoSParametersAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABLevelQoSParametersFieldExtCount(v *ERABLevelQoSParameters) *int64   { return &v.extCount }
func BridgeERABLevelQoSParametersFieldExtData(v *ERABLevelQoSParameters) *[][]byte { return &v.extData }
func BridgeERABLevelQoSParametersFieldExtOrigin(v *ERABLevelQoSParameters) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABLevelQoSParametersFieldExtPresent(v *ERABLevelQoSParameters) *[]bool {
	return &v.extPresent
}
func BridgeERABLevelQoSParametersFieldExtWire(v *ERABLevelQoSParameters) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABLevelQoSParametersFieldIEExtensionsIndef(v *ERABLevelQoSParameters) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABLevelQoSParametersFieldPerExtPadding(v *ERABLevelQoSParameters) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABLevelQoSParametersFieldPerPadding(v *ERABLevelQoSParameters) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABLevelQoSParametersFieldReceived(v *ERABLevelQoSParameters) *bool { return &v.received }
func BridgeERABLevelQoSParametersFieldReceivedAbsolute(v *ERABLevelQoSParameters) *bool {
	return &v.receivedAbsolute
}
func BridgeERABLevelQoSParametersFieldReceivedBytes(v *ERABLevelQoSParameters) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABLevelQoSParametersFieldReceivedLocation(v *ERABLevelQoSParameters) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABLevelQoSParametersFieldReplay(v *ERABLevelQoSParameters) *aper.Snapshot {
	return &v.replay
}
func BridgeERABLevelQoSParametersFieldStream(v *ERABLevelQoSParameters) *aper.WireSpan {
	return &v.stream
}
func BridgeERABLevelQoSParametersFieldWithoutReplay(v *ERABLevelQoSParameters) *bool {
	return &v.withoutReplay
}
func BridgeERABLevelQoSParametersMethodMarshalAPERBudget(v *ERABLevelQoSParameters, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERBudgetValue(v *ERABLevelQoSParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERChanged(v *ERABLevelQoSParameters, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERChangedValue(v *ERABLevelQoSParameters, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERLegacy(v *ERABLevelQoSParameters) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABLevelQoSParametersMethodMarshalAPERNewValue(v *ERABLevelQoSParameters, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERPlanned(v *ERABLevelQoSParameters, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABLevelQoSParametersMethodMarshalAPERTo(v *ERABLevelQoSParameters, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABLevelQoSParametersMethodUnmarshalAPERFrom(v *ERABLevelQoSParameters, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABLevelQoSParametersMethodUnmarshalAPERLegacy(v *ERABLevelQoSParameters, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABLevelQoSParametersMethodUnmarshalAPERWithOptions(v *ERABLevelQoSParameters, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABLevelQoSParametersValueCodecFieldCapture(v *ERABLevelQoSParametersValueCodec) *func(ERABLevelQoSParameters, aper.DecodeState) (ERABLevelQoSParameters, aper.Snapshot) {
	return &v.capture
}
func BridgeERABLevelQoSParametersValueCodecFieldCompare(v *ERABLevelQoSParametersValueCodec) *func(ERABLevelQoSParameters, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABLevelQoSParametersValueCodecFieldContext(v *ERABLevelQoSParametersValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABLevelQoSParametersValueCodecFieldDecode(v *ERABLevelQoSParametersValueCodec) *func([]byte, aper.DecodeState) (ERABLevelQoSParameters, error) {
	return &v.decode
}
func BridgeERABLevelQoSParametersValueCodecFieldEncode(v *ERABLevelQoSParametersValueCodec) *func(ERABLevelQoSParameters, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABLevelQoSParametersValueCodecFieldPath(v *ERABLevelQoSParametersValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABLevelQoSParametersValueCodecMethodEncodeBudgetValue(v ERABLevelQoSParametersValueCodec, a0 ERABLevelQoSParameters, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABLevelQoSParametersValueCodecMethodEncodeChanged(v ERABLevelQoSParametersValueCodec, a0 ERABLevelQoSParameters, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEUTRANcellLoadReportingResponseAPERValueFieldContext(v *EUTRANcellLoadReportingResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANcellLoadReportingResponseAPERValueFieldReceived(v *EUTRANcellLoadReportingResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEUTRANcellLoadReportingResponseAPERValueFieldReplay(v *EUTRANcellLoadReportingResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEUTRANcellLoadReportingResponseAPERValueFieldWithoutReplay(v *EUTRANcellLoadReportingResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldCapture(v *EUTRANcellLoadReportingResponseValueCodec) *func(s17.EUTRANcellLoadReportingResponse, aper.DecodeState) (s17.EUTRANcellLoadReportingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldCompare(v *EUTRANcellLoadReportingResponseValueCodec) *func(s17.EUTRANcellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldContext(v *EUTRANcellLoadReportingResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldDecode(v *EUTRANcellLoadReportingResponseValueCodec) *func([]byte, aper.DecodeState) (s17.EUTRANcellLoadReportingResponse, error) {
	return &v.decode
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldEncode(v *EUTRANcellLoadReportingResponseValueCodec) *func(s17.EUTRANcellLoadReportingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANcellLoadReportingResponseValueCodecFieldPath(v *EUTRANcellLoadReportingResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeEUTRANcellLoadReportingResponseValueCodecMethodEncodeBudgetValue(v EUTRANcellLoadReportingResponseValueCodec, a0 s17.EUTRANcellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEUTRANcellLoadReportingResponseValueCodecMethodEncodeChanged(v EUTRANcellLoadReportingResponseValueCodec, a0 s17.EUTRANcellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEventTriggeredCellLoadReportingRequestAPERValueFieldContext(v *EventTriggeredCellLoadReportingRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggeredCellLoadReportingRequestAPERValueFieldReceived(v *EventTriggeredCellLoadReportingRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEventTriggeredCellLoadReportingRequestAPERValueFieldReplay(v *EventTriggeredCellLoadReportingRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggeredCellLoadReportingRequestAPERValueFieldWithoutReplay(v *EventTriggeredCellLoadReportingRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggeredCellLoadReportingRequestFieldExtCount(v *EventTriggeredCellLoadReportingRequest) *int64 {
	return &v.extCount
}
func BridgeEventTriggeredCellLoadReportingRequestFieldExtData(v *EventTriggeredCellLoadReportingRequest) *[][]byte {
	return &v.extData
}
func BridgeEventTriggeredCellLoadReportingRequestFieldExtOrigin(v *EventTriggeredCellLoadReportingRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEventTriggeredCellLoadReportingRequestFieldExtPresent(v *EventTriggeredCellLoadReportingRequest) *[]bool {
	return &v.extPresent
}
func BridgeEventTriggeredCellLoadReportingRequestFieldExtWire(v *EventTriggeredCellLoadReportingRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEventTriggeredCellLoadReportingRequestFieldPerExtPadding(v *EventTriggeredCellLoadReportingRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEventTriggeredCellLoadReportingRequestFieldPerPadding(v *EventTriggeredCellLoadReportingRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEventTriggeredCellLoadReportingRequestFieldReceived(v *EventTriggeredCellLoadReportingRequest) *bool {
	return &v.received
}
func BridgeEventTriggeredCellLoadReportingRequestFieldReceivedAbsolute(v *EventTriggeredCellLoadReportingRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeEventTriggeredCellLoadReportingRequestFieldReceivedBytes(v *EventTriggeredCellLoadReportingRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEventTriggeredCellLoadReportingRequestFieldReceivedLocation(v *EventTriggeredCellLoadReportingRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeEventTriggeredCellLoadReportingRequestFieldReplay(v *EventTriggeredCellLoadReportingRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggeredCellLoadReportingRequestFieldStream(v *EventTriggeredCellLoadReportingRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeEventTriggeredCellLoadReportingRequestFieldWithoutReplay(v *EventTriggeredCellLoadReportingRequest) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERBudget(v *EventTriggeredCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERBudgetValue(v *EventTriggeredCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERChanged(v *EventTriggeredCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERChangedValue(v *EventTriggeredCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERLegacy(v *EventTriggeredCellLoadReportingRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERNewValue(v *EventTriggeredCellLoadReportingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERPlanned(v *EventTriggeredCellLoadReportingRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERTo(v *EventTriggeredCellLoadReportingRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodUnmarshalAPERFrom(v *EventTriggeredCellLoadReportingRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodUnmarshalAPERLegacy(v *EventTriggeredCellLoadReportingRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEventTriggeredCellLoadReportingRequestMethodUnmarshalAPERWithOptions(v *EventTriggeredCellLoadReportingRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldCapture(v *EventTriggeredCellLoadReportingRequestValueCodec) *func(EventTriggeredCellLoadReportingRequest, aper.DecodeState) (EventTriggeredCellLoadReportingRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldCompare(v *EventTriggeredCellLoadReportingRequestValueCodec) *func(EventTriggeredCellLoadReportingRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldContext(v *EventTriggeredCellLoadReportingRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldDecode(v *EventTriggeredCellLoadReportingRequestValueCodec) *func([]byte, aper.DecodeState) (EventTriggeredCellLoadReportingRequest, error) {
	return &v.decode
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldEncode(v *EventTriggeredCellLoadReportingRequestValueCodec) *func(EventTriggeredCellLoadReportingRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecFieldPath(v *EventTriggeredCellLoadReportingRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecMethodEncodeBudgetValue(v EventTriggeredCellLoadReportingRequestValueCodec, a0 EventTriggeredCellLoadReportingRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingRequestValueCodecMethodEncodeChanged(v EventTriggeredCellLoadReportingRequestValueCodec, a0 EventTriggeredCellLoadReportingRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEventTriggeredCellLoadReportingResponseAPERValueFieldContext(v *EventTriggeredCellLoadReportingResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggeredCellLoadReportingResponseAPERValueFieldReceived(v *EventTriggeredCellLoadReportingResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEventTriggeredCellLoadReportingResponseAPERValueFieldReplay(v *EventTriggeredCellLoadReportingResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggeredCellLoadReportingResponseAPERValueFieldWithoutReplay(v *EventTriggeredCellLoadReportingResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggeredCellLoadReportingResponseFieldExtCount(v *EventTriggeredCellLoadReportingResponse) *int64 {
	return &v.extCount
}
func BridgeEventTriggeredCellLoadReportingResponseFieldExtData(v *EventTriggeredCellLoadReportingResponse) *[][]byte {
	return &v.extData
}
func BridgeEventTriggeredCellLoadReportingResponseFieldExtOrigin(v *EventTriggeredCellLoadReportingResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEventTriggeredCellLoadReportingResponseFieldExtPresent(v *EventTriggeredCellLoadReportingResponse) *[]bool {
	return &v.extPresent
}
func BridgeEventTriggeredCellLoadReportingResponseFieldExtWire(v *EventTriggeredCellLoadReportingResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEventTriggeredCellLoadReportingResponseFieldPerExtPadding(v *EventTriggeredCellLoadReportingResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEventTriggeredCellLoadReportingResponseFieldPerPadding(v *EventTriggeredCellLoadReportingResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEventTriggeredCellLoadReportingResponseFieldReceived(v *EventTriggeredCellLoadReportingResponse) *bool {
	return &v.received
}
func BridgeEventTriggeredCellLoadReportingResponseFieldReceivedAbsolute(v *EventTriggeredCellLoadReportingResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeEventTriggeredCellLoadReportingResponseFieldReceivedBytes(v *EventTriggeredCellLoadReportingResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEventTriggeredCellLoadReportingResponseFieldReceivedLocation(v *EventTriggeredCellLoadReportingResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeEventTriggeredCellLoadReportingResponseFieldReplay(v *EventTriggeredCellLoadReportingResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggeredCellLoadReportingResponseFieldStream(v *EventTriggeredCellLoadReportingResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeEventTriggeredCellLoadReportingResponseFieldWithoutReplay(v *EventTriggeredCellLoadReportingResponse) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERBudget(v *EventTriggeredCellLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERBudgetValue(v *EventTriggeredCellLoadReportingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERChanged(v *EventTriggeredCellLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERChangedValue(v *EventTriggeredCellLoadReportingResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERLegacy(v *EventTriggeredCellLoadReportingResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERNewValue(v *EventTriggeredCellLoadReportingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERPlanned(v *EventTriggeredCellLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERTo(v *EventTriggeredCellLoadReportingResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodUnmarshalAPERFrom(v *EventTriggeredCellLoadReportingResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodUnmarshalAPERLegacy(v *EventTriggeredCellLoadReportingResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEventTriggeredCellLoadReportingResponseMethodUnmarshalAPERWithOptions(v *EventTriggeredCellLoadReportingResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldCapture(v *EventTriggeredCellLoadReportingResponseValueCodec) *func(EventTriggeredCellLoadReportingResponse, aper.DecodeState) (EventTriggeredCellLoadReportingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldCompare(v *EventTriggeredCellLoadReportingResponseValueCodec) *func(EventTriggeredCellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldContext(v *EventTriggeredCellLoadReportingResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldDecode(v *EventTriggeredCellLoadReportingResponseValueCodec) *func([]byte, aper.DecodeState) (EventTriggeredCellLoadReportingResponse, error) {
	return &v.decode
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldEncode(v *EventTriggeredCellLoadReportingResponseValueCodec) *func(EventTriggeredCellLoadReportingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecFieldPath(v *EventTriggeredCellLoadReportingResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecMethodEncodeBudgetValue(v EventTriggeredCellLoadReportingResponseValueCodec, a0 EventTriggeredCellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEventTriggeredCellLoadReportingResponseValueCodecMethodEncodeChanged(v EventTriggeredCellLoadReportingResponseValueCodec, a0 EventTriggeredCellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeExpectedUEActivityBehaviourAPERValueFieldContext(v *ExpectedUEActivityBehaviourAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEActivityBehaviourAPERValueFieldReceived(v *ExpectedUEActivityBehaviourAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeExpectedUEActivityBehaviourAPERValueFieldReplay(v *ExpectedUEActivityBehaviourAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeExpectedUEActivityBehaviourAPERValueFieldWithoutReplay(v *ExpectedUEActivityBehaviourAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEActivityBehaviourFieldExtCount(v *ExpectedUEActivityBehaviour) *int64 {
	return &v.extCount
}
func BridgeExpectedUEActivityBehaviourFieldExtData(v *ExpectedUEActivityBehaviour) *[][]byte {
	return &v.extData
}
func BridgeExpectedUEActivityBehaviourFieldExtOrigin(v *ExpectedUEActivityBehaviour) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeExpectedUEActivityBehaviourFieldExtPresent(v *ExpectedUEActivityBehaviour) *[]bool {
	return &v.extPresent
}
func BridgeExpectedUEActivityBehaviourFieldExtWire(v *ExpectedUEActivityBehaviour) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeExpectedUEActivityBehaviourFieldIEExtensionsIndef(v *ExpectedUEActivityBehaviour) *bool {
	return &v.iEExtensionsIndef
}
func BridgeExpectedUEActivityBehaviourFieldPerExtPadding(v *ExpectedUEActivityBehaviour) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeExpectedUEActivityBehaviourFieldPerPadding(v *ExpectedUEActivityBehaviour) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeExpectedUEActivityBehaviourFieldReceived(v *ExpectedUEActivityBehaviour) *bool {
	return &v.received
}
func BridgeExpectedUEActivityBehaviourFieldReceivedAbsolute(v *ExpectedUEActivityBehaviour) *bool {
	return &v.receivedAbsolute
}
func BridgeExpectedUEActivityBehaviourFieldReceivedBytes(v *ExpectedUEActivityBehaviour) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeExpectedUEActivityBehaviourFieldReceivedLocation(v *ExpectedUEActivityBehaviour) *aper.Location {
	return &v.receivedLocation
}
func BridgeExpectedUEActivityBehaviourFieldReplay(v *ExpectedUEActivityBehaviour) *aper.Snapshot {
	return &v.replay
}
func BridgeExpectedUEActivityBehaviourFieldStream(v *ExpectedUEActivityBehaviour) *aper.WireSpan {
	return &v.stream
}
func BridgeExpectedUEActivityBehaviourFieldWithoutReplay(v *ExpectedUEActivityBehaviour) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERBudget(v *ExpectedUEActivityBehaviour, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERBudgetValue(v *ExpectedUEActivityBehaviour, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERChanged(v *ExpectedUEActivityBehaviour, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERChangedValue(v *ExpectedUEActivityBehaviour, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERLegacy(v *ExpectedUEActivityBehaviour) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERNewValue(v *ExpectedUEActivityBehaviour, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERPlanned(v *ExpectedUEActivityBehaviour, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeExpectedUEActivityBehaviourMethodMarshalAPERTo(v *ExpectedUEActivityBehaviour, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeExpectedUEActivityBehaviourMethodUnmarshalAPERFrom(v *ExpectedUEActivityBehaviour, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeExpectedUEActivityBehaviourMethodUnmarshalAPERLegacy(v *ExpectedUEActivityBehaviour, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeExpectedUEActivityBehaviourMethodUnmarshalAPERWithOptions(v *ExpectedUEActivityBehaviour, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldCapture(v *ExpectedUEActivityBehaviourValueCodec) *func(ExpectedUEActivityBehaviour, aper.DecodeState) (ExpectedUEActivityBehaviour, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldCompare(v *ExpectedUEActivityBehaviourValueCodec) *func(ExpectedUEActivityBehaviour, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldContext(v *ExpectedUEActivityBehaviourValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldDecode(v *ExpectedUEActivityBehaviourValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEActivityBehaviour, error) {
	return &v.decode
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldEncode(v *ExpectedUEActivityBehaviourValueCodec) *func(ExpectedUEActivityBehaviour, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEActivityBehaviourValueCodecFieldPath(v *ExpectedUEActivityBehaviourValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEActivityBehaviourValueCodecMethodEncodeBudgetValue(v ExpectedUEActivityBehaviourValueCodec, a0 ExpectedUEActivityBehaviour, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeExpectedUEActivityBehaviourValueCodecMethodEncodeChanged(v ExpectedUEActivityBehaviourValueCodec, a0 ExpectedUEActivityBehaviour, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeExpectedUEBehaviourAPERValueFieldContext(v *ExpectedUEBehaviourAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEBehaviourAPERValueFieldReceived(v *ExpectedUEBehaviourAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeExpectedUEBehaviourAPERValueFieldReplay(v *ExpectedUEBehaviourAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeExpectedUEBehaviourAPERValueFieldWithoutReplay(v *ExpectedUEBehaviourAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEBehaviourFieldExtCount(v *ExpectedUEBehaviour) *int64   { return &v.extCount }
func BridgeExpectedUEBehaviourFieldExtData(v *ExpectedUEBehaviour) *[][]byte { return &v.extData }
func BridgeExpectedUEBehaviourFieldExtOrigin(v *ExpectedUEBehaviour) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeExpectedUEBehaviourFieldExtPresent(v *ExpectedUEBehaviour) *[]bool { return &v.extPresent }
func BridgeExpectedUEBehaviourFieldExtWire(v *ExpectedUEBehaviour) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeExpectedUEBehaviourFieldIEExtensionsIndef(v *ExpectedUEBehaviour) *bool {
	return &v.iEExtensionsIndef
}
func BridgeExpectedUEBehaviourFieldPerExtPadding(v *ExpectedUEBehaviour) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeExpectedUEBehaviourFieldPerPadding(v *ExpectedUEBehaviour) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeExpectedUEBehaviourFieldReceived(v *ExpectedUEBehaviour) *bool { return &v.received }
func BridgeExpectedUEBehaviourFieldReceivedAbsolute(v *ExpectedUEBehaviour) *bool {
	return &v.receivedAbsolute
}
func BridgeExpectedUEBehaviourFieldReceivedBytes(v *ExpectedUEBehaviour) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeExpectedUEBehaviourFieldReceivedLocation(v *ExpectedUEBehaviour) *aper.Location {
	return &v.receivedLocation
}
func BridgeExpectedUEBehaviourFieldReplay(v *ExpectedUEBehaviour) *aper.Snapshot { return &v.replay }
func BridgeExpectedUEBehaviourFieldStream(v *ExpectedUEBehaviour) *aper.WireSpan { return &v.stream }
func BridgeExpectedUEBehaviourFieldWithoutReplay(v *ExpectedUEBehaviour) *bool {
	return &v.withoutReplay
}
func BridgeExpectedUEBehaviourMethodMarshalAPERBudget(v *ExpectedUEBehaviour, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERBudgetValue(v *ExpectedUEBehaviour, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERChanged(v *ExpectedUEBehaviour, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERChangedValue(v *ExpectedUEBehaviour, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERLegacy(v *ExpectedUEBehaviour) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeExpectedUEBehaviourMethodMarshalAPERNewValue(v *ExpectedUEBehaviour, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERPlanned(v *ExpectedUEBehaviour, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeExpectedUEBehaviourMethodMarshalAPERTo(v *ExpectedUEBehaviour, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeExpectedUEBehaviourMethodUnmarshalAPERFrom(v *ExpectedUEBehaviour, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeExpectedUEBehaviourMethodUnmarshalAPERLegacy(v *ExpectedUEBehaviour, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeExpectedUEBehaviourMethodUnmarshalAPERWithOptions(v *ExpectedUEBehaviour, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeExpectedUEBehaviourValueCodecFieldCapture(v *ExpectedUEBehaviourValueCodec) *func(ExpectedUEBehaviour, aper.DecodeState) (ExpectedUEBehaviour, aper.Snapshot) {
	return &v.capture
}
func BridgeExpectedUEBehaviourValueCodecFieldCompare(v *ExpectedUEBehaviourValueCodec) *func(ExpectedUEBehaviour, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExpectedUEBehaviourValueCodecFieldContext(v *ExpectedUEBehaviourValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExpectedUEBehaviourValueCodecFieldDecode(v *ExpectedUEBehaviourValueCodec) *func([]byte, aper.DecodeState) (ExpectedUEBehaviour, error) {
	return &v.decode
}
func BridgeExpectedUEBehaviourValueCodecFieldEncode(v *ExpectedUEBehaviourValueCodec) *func(ExpectedUEBehaviour, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExpectedUEBehaviourValueCodecFieldPath(v *ExpectedUEBehaviourValueCodec) *aper.Path {
	return &v.path
}
func BridgeExpectedUEBehaviourValueCodecMethodEncodeBudgetValue(v ExpectedUEBehaviourValueCodec, a0 ExpectedUEBehaviour, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeExpectedUEBehaviourValueCodecMethodEncodeChanged(v ExpectedUEBehaviourValueCodec, a0 ExpectedUEBehaviour, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeFiveGSTAIAPERValueFieldContext(v *FiveGSTAIAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveGSTAIAPERValueFieldReceived(v *FiveGSTAIAPERValue) *aper.WireSpan { return &v.received }
func BridgeFiveGSTAIAPERValueFieldReplay(v *FiveGSTAIAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeFiveGSTAIAPERValueFieldWithoutReplay(v *FiveGSTAIAPERValue) *bool     { return &v.withoutReplay }
func BridgeFiveGSTAIFieldExtCount(v *FiveGSTAI) *int64                           { return &v.extCount }
func BridgeFiveGSTAIFieldExtData(v *FiveGSTAI) *[][]byte                         { return &v.extData }
func BridgeFiveGSTAIFieldExtOrigin(v *FiveGSTAI) *[]aper.OpaqueOrigin            { return &v.extOrigin }
func BridgeFiveGSTAIFieldExtPresent(v *FiveGSTAI) *[]bool                        { return &v.extPresent }
func BridgeFiveGSTAIFieldExtWire(v *FiveGSTAI) *[]aper.WireSpan                  { return &v.extWire }
func BridgeFiveGSTAIFieldIEExtensionsIndef(v *FiveGSTAI) *bool                   { return &v.iEExtensionsIndef }
func BridgeFiveGSTAIFieldPerExtPadding(v *FiveGSTAI) *[]aper.CompletePadding     { return &v.perExtPadding }
func BridgeFiveGSTAIFieldPerPadding(v *FiveGSTAI) *aper.FinalPadding             { return &v.perPadding }
func BridgeFiveGSTAIFieldReceived(v *FiveGSTAI) *bool                            { return &v.received }
func BridgeFiveGSTAIFieldReceivedAbsolute(v *FiveGSTAI) *bool                    { return &v.receivedAbsolute }
func BridgeFiveGSTAIFieldReceivedBytes(v *FiveGSTAI) *aper.WireSpan              { return &v.receivedBytes }
func BridgeFiveGSTAIFieldReceivedLocation(v *FiveGSTAI) *aper.Location           { return &v.receivedLocation }
func BridgeFiveGSTAIFieldReplay(v *FiveGSTAI) *aper.Snapshot                     { return &v.replay }
func BridgeFiveGSTAIFieldStream(v *FiveGSTAI) *aper.WireSpan                     { return &v.stream }
func BridgeFiveGSTAIFieldWithoutReplay(v *FiveGSTAI) *bool                       { return &v.withoutReplay }
func BridgeFiveGSTAIMethodMarshalAPERBudget(v *FiveGSTAI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeFiveGSTAIMethodMarshalAPERBudgetValue(v *FiveGSTAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeFiveGSTAIMethodMarshalAPERChanged(v *FiveGSTAI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeFiveGSTAIMethodMarshalAPERChangedValue(v *FiveGSTAI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeFiveGSTAIMethodMarshalAPERLegacy(v *FiveGSTAI) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeFiveGSTAIMethodMarshalAPERNewValue(v *FiveGSTAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeFiveGSTAIMethodMarshalAPERPlanned(v *FiveGSTAI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeFiveGSTAIMethodMarshalAPERTo(v *FiveGSTAI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeFiveGSTAIMethodUnmarshalAPERFrom(v *FiveGSTAI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeFiveGSTAIMethodUnmarshalAPERLegacy(v *FiveGSTAI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeFiveGSTAIMethodUnmarshalAPERWithOptions(v *FiveGSTAI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeFiveGSTAIValueCodecFieldCapture(v *FiveGSTAIValueCodec) *func(FiveGSTAI, aper.DecodeState) (FiveGSTAI, aper.Snapshot) {
	return &v.capture
}
func BridgeFiveGSTAIValueCodecFieldCompare(v *FiveGSTAIValueCodec) *func(FiveGSTAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFiveGSTAIValueCodecFieldContext(v *FiveGSTAIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveGSTAIValueCodecFieldDecode(v *FiveGSTAIValueCodec) *func([]byte, aper.DecodeState) (FiveGSTAI, error) {
	return &v.decode
}
func BridgeFiveGSTAIValueCodecFieldEncode(v *FiveGSTAIValueCodec) *func(FiveGSTAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFiveGSTAIValueCodecFieldPath(v *FiveGSTAIValueCodec) *aper.Path { return &v.path }
func BridgeFiveGSTAIValueCodecMethodEncodeBudgetValue(v FiveGSTAIValueCodec, a0 FiveGSTAI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeFiveGSTAIValueCodecMethodEncodeChanged(v FiveGSTAIValueCodec, a0 FiveGSTAI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeForbiddenLAsAPERValueFieldContext(v *ForbiddenLAsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsAPERValueFieldReceived(v *ForbiddenLAsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeForbiddenLAsAPERValueFieldReplay(v *ForbiddenLAsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenLAsAPERValueFieldWithoutReplay(v *ForbiddenLAsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenLAsItemAPERValueFieldContext(v *ForbiddenLAsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsItemAPERValueFieldReceived(v *ForbiddenLAsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeForbiddenLAsItemAPERValueFieldReplay(v *ForbiddenLAsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenLAsItemAPERValueFieldWithoutReplay(v *ForbiddenLAsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenLAsItemFieldExtCount(v *ForbiddenLAsItem) *int64   { return &v.extCount }
func BridgeForbiddenLAsItemFieldExtData(v *ForbiddenLAsItem) *[][]byte { return &v.extData }
func BridgeForbiddenLAsItemFieldExtOrigin(v *ForbiddenLAsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeForbiddenLAsItemFieldExtPresent(v *ForbiddenLAsItem) *[]bool       { return &v.extPresent }
func BridgeForbiddenLAsItemFieldExtWire(v *ForbiddenLAsItem) *[]aper.WireSpan { return &v.extWire }
func BridgeForbiddenLAsItemFieldForbiddenLACsIndef(v *ForbiddenLAsItem) *bool {
	return &v.forbiddenLACsIndef
}
func BridgeForbiddenLAsItemFieldIEExtensionsIndef(v *ForbiddenLAsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeForbiddenLAsItemFieldPerExtPadding(v *ForbiddenLAsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeForbiddenLAsItemFieldPerPadding(v *ForbiddenLAsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeForbiddenLAsItemFieldReceived(v *ForbiddenLAsItem) *bool { return &v.received }
func BridgeForbiddenLAsItemFieldReceivedAbsolute(v *ForbiddenLAsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenLAsItemFieldReceivedBytes(v *ForbiddenLAsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenLAsItemFieldReceivedLocation(v *ForbiddenLAsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenLAsItemFieldReplay(v *ForbiddenLAsItem) *aper.Snapshot { return &v.replay }
func BridgeForbiddenLAsItemFieldStream(v *ForbiddenLAsItem) *aper.WireSpan { return &v.stream }
func BridgeForbiddenLAsItemFieldWithoutReplay(v *ForbiddenLAsItem) *bool   { return &v.withoutReplay }
func BridgeForbiddenLAsItemMethodMarshalAPERBudget(v *ForbiddenLAsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenLAsItemMethodMarshalAPERBudgetValue(v *ForbiddenLAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenLAsItemMethodMarshalAPERChanged(v *ForbiddenLAsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenLAsItemMethodMarshalAPERChangedValue(v *ForbiddenLAsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenLAsItemMethodMarshalAPERLegacy(v *ForbiddenLAsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenLAsItemMethodMarshalAPERNewValue(v *ForbiddenLAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenLAsItemMethodMarshalAPERPlanned(v *ForbiddenLAsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenLAsItemMethodMarshalAPERTo(v *ForbiddenLAsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeForbiddenLAsItemMethodUnmarshalAPERFrom(v *ForbiddenLAsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeForbiddenLAsItemMethodUnmarshalAPERLegacy(v *ForbiddenLAsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenLAsItemMethodUnmarshalAPERWithOptions(v *ForbiddenLAsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenLAsItemValueCodecFieldCapture(v *ForbiddenLAsItemValueCodec) *func(ForbiddenLAsItem, aper.DecodeState) (ForbiddenLAsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenLAsItemValueCodecFieldCompare(v *ForbiddenLAsItemValueCodec) *func(ForbiddenLAsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenLAsItemValueCodecFieldContext(v *ForbiddenLAsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsItemValueCodecFieldDecode(v *ForbiddenLAsItemValueCodec) *func([]byte, aper.DecodeState) (ForbiddenLAsItem, error) {
	return &v.decode
}
func BridgeForbiddenLAsItemValueCodecFieldEncode(v *ForbiddenLAsItemValueCodec) *func(ForbiddenLAsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenLAsItemValueCodecFieldPath(v *ForbiddenLAsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenLAsItemValueCodecMethodEncodeBudgetValue(v ForbiddenLAsItemValueCodec, a0 ForbiddenLAsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeForbiddenLAsItemValueCodecMethodEncodeChanged(v ForbiddenLAsItemValueCodec, a0 ForbiddenLAsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeForbiddenLAsValueCodecFieldCapture(v *ForbiddenLAsValueCodec) *func(ForbiddenLAs, aper.DecodeState) (ForbiddenLAs, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenLAsValueCodecFieldCompare(v *ForbiddenLAsValueCodec) *func(ForbiddenLAs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenLAsValueCodecFieldContext(v *ForbiddenLAsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLAsValueCodecFieldDecode(v *ForbiddenLAsValueCodec) *func([]byte, aper.DecodeState) (ForbiddenLAs, error) {
	return &v.decode
}
func BridgeForbiddenLAsValueCodecFieldEncode(v *ForbiddenLAsValueCodec) *func(ForbiddenLAs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenLAsValueCodecFieldPath(v *ForbiddenLAsValueCodec) *aper.Path { return &v.path }
func BridgeForbiddenLAsValueCodecMethodEncodeBudgetValue(v ForbiddenLAsValueCodec, a0 ForbiddenLAs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeForbiddenLAsValueCodecMethodEncodeChanged(v ForbiddenLAsValueCodec, a0 ForbiddenLAs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeForbiddenTAsAPERValueFieldContext(v *ForbiddenTAsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsAPERValueFieldReceived(v *ForbiddenTAsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeForbiddenTAsAPERValueFieldReplay(v *ForbiddenTAsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenTAsAPERValueFieldWithoutReplay(v *ForbiddenTAsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenTAsItemAPERValueFieldContext(v *ForbiddenTAsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsItemAPERValueFieldReceived(v *ForbiddenTAsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeForbiddenTAsItemAPERValueFieldReplay(v *ForbiddenTAsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeForbiddenTAsItemAPERValueFieldWithoutReplay(v *ForbiddenTAsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeForbiddenTAsItemFieldExtCount(v *ForbiddenTAsItem) *int64   { return &v.extCount }
func BridgeForbiddenTAsItemFieldExtData(v *ForbiddenTAsItem) *[][]byte { return &v.extData }
func BridgeForbiddenTAsItemFieldExtOrigin(v *ForbiddenTAsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeForbiddenTAsItemFieldExtPresent(v *ForbiddenTAsItem) *[]bool       { return &v.extPresent }
func BridgeForbiddenTAsItemFieldExtWire(v *ForbiddenTAsItem) *[]aper.WireSpan { return &v.extWire }
func BridgeForbiddenTAsItemFieldForbiddenTACsIndef(v *ForbiddenTAsItem) *bool {
	return &v.forbiddenTACsIndef
}
func BridgeForbiddenTAsItemFieldIEExtensionsIndef(v *ForbiddenTAsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeForbiddenTAsItemFieldPerExtPadding(v *ForbiddenTAsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeForbiddenTAsItemFieldPerPadding(v *ForbiddenTAsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeForbiddenTAsItemFieldReceived(v *ForbiddenTAsItem) *bool { return &v.received }
func BridgeForbiddenTAsItemFieldReceivedAbsolute(v *ForbiddenTAsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeForbiddenTAsItemFieldReceivedBytes(v *ForbiddenTAsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeForbiddenTAsItemFieldReceivedLocation(v *ForbiddenTAsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeForbiddenTAsItemFieldReplay(v *ForbiddenTAsItem) *aper.Snapshot { return &v.replay }
func BridgeForbiddenTAsItemFieldStream(v *ForbiddenTAsItem) *aper.WireSpan { return &v.stream }
func BridgeForbiddenTAsItemFieldWithoutReplay(v *ForbiddenTAsItem) *bool   { return &v.withoutReplay }
func BridgeForbiddenTAsItemMethodMarshalAPERBudget(v *ForbiddenTAsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeForbiddenTAsItemMethodMarshalAPERBudgetValue(v *ForbiddenTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeForbiddenTAsItemMethodMarshalAPERChanged(v *ForbiddenTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeForbiddenTAsItemMethodMarshalAPERChangedValue(v *ForbiddenTAsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeForbiddenTAsItemMethodMarshalAPERLegacy(v *ForbiddenTAsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeForbiddenTAsItemMethodMarshalAPERNewValue(v *ForbiddenTAsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeForbiddenTAsItemMethodMarshalAPERPlanned(v *ForbiddenTAsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeForbiddenTAsItemMethodMarshalAPERTo(v *ForbiddenTAsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeForbiddenTAsItemMethodUnmarshalAPERFrom(v *ForbiddenTAsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeForbiddenTAsItemMethodUnmarshalAPERLegacy(v *ForbiddenTAsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeForbiddenTAsItemMethodUnmarshalAPERWithOptions(v *ForbiddenTAsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeForbiddenTAsItemValueCodecFieldCapture(v *ForbiddenTAsItemValueCodec) *func(ForbiddenTAsItem, aper.DecodeState) (ForbiddenTAsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenTAsItemValueCodecFieldCompare(v *ForbiddenTAsItemValueCodec) *func(ForbiddenTAsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenTAsItemValueCodecFieldContext(v *ForbiddenTAsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsItemValueCodecFieldDecode(v *ForbiddenTAsItemValueCodec) *func([]byte, aper.DecodeState) (ForbiddenTAsItem, error) {
	return &v.decode
}
func BridgeForbiddenTAsItemValueCodecFieldEncode(v *ForbiddenTAsItemValueCodec) *func(ForbiddenTAsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenTAsItemValueCodecFieldPath(v *ForbiddenTAsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenTAsItemValueCodecMethodEncodeBudgetValue(v ForbiddenTAsItemValueCodec, a0 ForbiddenTAsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeForbiddenTAsItemValueCodecMethodEncodeChanged(v ForbiddenTAsItemValueCodec, a0 ForbiddenTAsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeForbiddenTAsValueCodecFieldCapture(v *ForbiddenTAsValueCodec) *func(ForbiddenTAs, aper.DecodeState) (ForbiddenTAs, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenTAsValueCodecFieldCompare(v *ForbiddenTAsValueCodec) *func(ForbiddenTAs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenTAsValueCodecFieldContext(v *ForbiddenTAsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTAsValueCodecFieldDecode(v *ForbiddenTAsValueCodec) *func([]byte, aper.DecodeState) (ForbiddenTAs, error) {
	return &v.decode
}
func BridgeForbiddenTAsValueCodecFieldEncode(v *ForbiddenTAsValueCodec) *func(ForbiddenTAs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenTAsValueCodecFieldPath(v *ForbiddenTAsValueCodec) *aper.Path { return &v.path }
func BridgeForbiddenTAsValueCodecMethodEncodeBudgetValue(v ForbiddenTAsValueCodec, a0 ForbiddenTAs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeForbiddenTAsValueCodecMethodEncodeChanged(v ForbiddenTAsValueCodec, a0 ForbiddenTAs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGBRQosInformationAPERValueFieldContext(v *GBRQosInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGBRQosInformationAPERValueFieldReceived(v *GBRQosInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGBRQosInformationAPERValueFieldReplay(v *GBRQosInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeGBRQosInformationAPERValueFieldWithoutReplay(v *GBRQosInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGBRQosInformationFieldExtCount(v *GBRQosInformation) *int64   { return &v.extCount }
func BridgeGBRQosInformationFieldExtData(v *GBRQosInformation) *[][]byte { return &v.extData }
func BridgeGBRQosInformationFieldExtOrigin(v *GBRQosInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeGBRQosInformationFieldExtPresent(v *GBRQosInformation) *[]bool       { return &v.extPresent }
func BridgeGBRQosInformationFieldExtWire(v *GBRQosInformation) *[]aper.WireSpan { return &v.extWire }
func BridgeGBRQosInformationFieldIEExtensionsIndef(v *GBRQosInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeGBRQosInformationFieldPerExtPadding(v *GBRQosInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeGBRQosInformationFieldPerPadding(v *GBRQosInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeGBRQosInformationFieldReceived(v *GBRQosInformation) *bool { return &v.received }
func BridgeGBRQosInformationFieldReceivedAbsolute(v *GBRQosInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeGBRQosInformationFieldReceivedBytes(v *GBRQosInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeGBRQosInformationFieldReceivedLocation(v *GBRQosInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeGBRQosInformationFieldReplay(v *GBRQosInformation) *aper.Snapshot { return &v.replay }
func BridgeGBRQosInformationFieldStream(v *GBRQosInformation) *aper.WireSpan { return &v.stream }
func BridgeGBRQosInformationFieldWithoutReplay(v *GBRQosInformation) *bool   { return &v.withoutReplay }
func BridgeGBRQosInformationMethodMarshalAPERBudget(v *GBRQosInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGBRQosInformationMethodMarshalAPERBudgetValue(v *GBRQosInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGBRQosInformationMethodMarshalAPERChanged(v *GBRQosInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGBRQosInformationMethodMarshalAPERChangedValue(v *GBRQosInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGBRQosInformationMethodMarshalAPERLegacy(v *GBRQosInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGBRQosInformationMethodMarshalAPERNewValue(v *GBRQosInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGBRQosInformationMethodMarshalAPERPlanned(v *GBRQosInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGBRQosInformationMethodMarshalAPERTo(v *GBRQosInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGBRQosInformationMethodUnmarshalAPERFrom(v *GBRQosInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGBRQosInformationMethodUnmarshalAPERLegacy(v *GBRQosInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGBRQosInformationMethodUnmarshalAPERWithOptions(v *GBRQosInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGBRQosInformationValueCodecFieldCapture(v *GBRQosInformationValueCodec) *func(GBRQosInformation, aper.DecodeState) (GBRQosInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeGBRQosInformationValueCodecFieldCompare(v *GBRQosInformationValueCodec) *func(GBRQosInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGBRQosInformationValueCodecFieldContext(v *GBRQosInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGBRQosInformationValueCodecFieldDecode(v *GBRQosInformationValueCodec) *func([]byte, aper.DecodeState) (GBRQosInformation, error) {
	return &v.decode
}
func BridgeGBRQosInformationValueCodecFieldEncode(v *GBRQosInformationValueCodec) *func(GBRQosInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGBRQosInformationValueCodecFieldPath(v *GBRQosInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeGBRQosInformationValueCodecMethodEncodeBudgetValue(v GBRQosInformationValueCodec, a0 GBRQosInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGBRQosInformationValueCodecMethodEncodeChanged(v GBRQosInformationValueCodec, a0 GBRQosInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGERANCellIDAPERValueFieldContext(v *GERANCellIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGERANCellIDAPERValueFieldReceived(v *GERANCellIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGERANCellIDAPERValueFieldReplay(v *GERANCellIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeGERANCellIDAPERValueFieldWithoutReplay(v *GERANCellIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGERANCellIDFieldExtCount(v *GERANCellID) *int64                { return &v.extCount }
func BridgeGERANCellIDFieldExtData(v *GERANCellID) *[][]byte              { return &v.extData }
func BridgeGERANCellIDFieldExtOrigin(v *GERANCellID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeGERANCellIDFieldExtPresent(v *GERANCellID) *[]bool             { return &v.extPresent }
func BridgeGERANCellIDFieldExtWire(v *GERANCellID) *[]aper.WireSpan       { return &v.extWire }
func BridgeGERANCellIDFieldIEExtensionsIndef(v *GERANCellID) *bool        { return &v.iEExtensionsIndef }
func BridgeGERANCellIDFieldPerExtPadding(v *GERANCellID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeGERANCellIDFieldPerPadding(v *GERANCellID) *aper.FinalPadding { return &v.perPadding }
func BridgeGERANCellIDFieldReceived(v *GERANCellID) *bool                { return &v.received }
func BridgeGERANCellIDFieldReceivedAbsolute(v *GERANCellID) *bool        { return &v.receivedAbsolute }
func BridgeGERANCellIDFieldReceivedBytes(v *GERANCellID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeGERANCellIDFieldReceivedLocation(v *GERANCellID) *aper.Location {
	return &v.receivedLocation
}
func BridgeGERANCellIDFieldReplay(v *GERANCellID) *aper.Snapshot { return &v.replay }
func BridgeGERANCellIDFieldStream(v *GERANCellID) *aper.WireSpan { return &v.stream }
func BridgeGERANCellIDFieldWithoutReplay(v *GERANCellID) *bool   { return &v.withoutReplay }
func BridgeGERANCellIDMethodMarshalAPERBudget(v *GERANCellID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGERANCellIDMethodMarshalAPERBudgetValue(v *GERANCellID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGERANCellIDMethodMarshalAPERChanged(v *GERANCellID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGERANCellIDMethodMarshalAPERChangedValue(v *GERANCellID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGERANCellIDMethodMarshalAPERLegacy(v *GERANCellID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGERANCellIDMethodMarshalAPERNewValue(v *GERANCellID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGERANCellIDMethodMarshalAPERPlanned(v *GERANCellID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGERANCellIDMethodMarshalAPERTo(v *GERANCellID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGERANCellIDMethodUnmarshalAPERFrom(v *GERANCellID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGERANCellIDMethodUnmarshalAPERLegacy(v *GERANCellID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGERANCellIDMethodUnmarshalAPERWithOptions(v *GERANCellID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGERANCellIDValueCodecFieldCapture(v *GERANCellIDValueCodec) *func(GERANCellID, aper.DecodeState) (GERANCellID, aper.Snapshot) {
	return &v.capture
}
func BridgeGERANCellIDValueCodecFieldCompare(v *GERANCellIDValueCodec) *func(GERANCellID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGERANCellIDValueCodecFieldContext(v *GERANCellIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGERANCellIDValueCodecFieldDecode(v *GERANCellIDValueCodec) *func([]byte, aper.DecodeState) (GERANCellID, error) {
	return &v.decode
}
func BridgeGERANCellIDValueCodecFieldEncode(v *GERANCellIDValueCodec) *func(GERANCellID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGERANCellIDValueCodecFieldPath(v *GERANCellIDValueCodec) *aper.Path { return &v.path }
func BridgeGERANCellIDValueCodecMethodEncodeBudgetValue(v GERANCellIDValueCodec, a0 GERANCellID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGERANCellIDValueCodecMethodEncodeChanged(v GERANCellIDValueCodec, a0 GERANCellID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGNBAPERValueFieldContext(v *GNBAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeGNBAPERValueFieldReceived(v *GNBAPERValue) *aper.WireSpan         { return &v.received }
func BridgeGNBAPERValueFieldReplay(v *GNBAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeGNBAPERValueFieldWithoutReplay(v *GNBAPERValue) *bool             { return &v.withoutReplay }
func BridgeGNBFieldExtCount(v *GNB) *int64                                   { return &v.extCount }
func BridgeGNBFieldExtData(v *GNB) *[][]byte                                 { return &v.extData }
func BridgeGNBFieldExtOrigin(v *GNB) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeGNBFieldExtPresent(v *GNB) *[]bool                                { return &v.extPresent }
func BridgeGNBFieldExtWire(v *GNB) *[]aper.WireSpan                          { return &v.extWire }
func BridgeGNBFieldIEExtensionsIndef(v *GNB) *bool                           { return &v.iEExtensionsIndef }
func BridgeGNBFieldPerExtPadding(v *GNB) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeGNBFieldPerPadding(v *GNB) *aper.FinalPadding                     { return &v.perPadding }
func BridgeGNBFieldReceived(v *GNB) *bool                                    { return &v.received }
func BridgeGNBFieldReceivedAbsolute(v *GNB) *bool                            { return &v.receivedAbsolute }
func BridgeGNBFieldReceivedBytes(v *GNB) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeGNBFieldReceivedLocation(v *GNB) *aper.Location                   { return &v.receivedLocation }
func BridgeGNBFieldReplay(v *GNB) *aper.Snapshot                             { return &v.replay }
func BridgeGNBFieldStream(v *GNB) *aper.WireSpan                             { return &v.stream }
func BridgeGNBFieldWithoutReplay(v *GNB) *bool                               { return &v.withoutReplay }
func BridgeGNBIdentityAPERValueFieldContext(v *GNBIdentityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGNBIdentityAPERValueFieldReceived(v *GNBIdentityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGNBIdentityAPERValueFieldReplay(v *GNBIdentityAPERValue) *aper.Snapshot { return &v.replay }
func BridgeGNBIdentityAPERValueFieldWithoutReplay(v *GNBIdentityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGNBIdentityFieldPerOpenTypePadding(v *GNBIdentity) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeGNBIdentityFieldPerPadding(v *GNBIdentity) *aper.CompletePadding { return &v.perPadding }
func BridgeGNBIdentityFieldReceived(v *GNBIdentity) *bool                   { return &v.received }
func BridgeGNBIdentityFieldReceivedAbsolute(v *GNBIdentity) *bool           { return &v.receivedAbsolute }
func BridgeGNBIdentityFieldReceivedBytes(v *GNBIdentity) *aper.WireSpan     { return &v.receivedBytes }
func BridgeGNBIdentityFieldReceivedLocation(v *GNBIdentity) *aper.Location {
	return &v.receivedLocation
}
func BridgeGNBIdentityFieldReplay(v *GNBIdentity) *aper.Snapshot { return &v.replay }
func BridgeGNBIdentityFieldStream(v *GNBIdentity) *aper.WireSpan { return &v.stream }
func BridgeGNBIdentityFieldWithoutReplay(v *GNBIdentity) *bool   { return &v.withoutReplay }
func BridgeGNBIdentityMethodMarshalAPERBudget(v *GNBIdentity, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGNBIdentityMethodMarshalAPERBudgetValue(v *GNBIdentity, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGNBIdentityMethodMarshalAPERChanged(v *GNBIdentity, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGNBIdentityMethodMarshalAPERChangedValue(v *GNBIdentity, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGNBIdentityMethodMarshalAPERLegacy(v *GNBIdentity) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGNBIdentityMethodMarshalAPERNewValue(v *GNBIdentity, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGNBIdentityMethodMarshalAPERPlanned(v *GNBIdentity, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGNBIdentityMethodMarshalAPERTo(v *GNBIdentity, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGNBIdentityMethodUnmarshalAPERFrom(v *GNBIdentity, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGNBIdentityMethodUnmarshalAPERLegacy(v *GNBIdentity, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGNBIdentityMethodUnmarshalAPERWithOptions(v *GNBIdentity, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGNBIdentityValueCodecFieldCapture(v *GNBIdentityValueCodec) *func(GNBIdentity, aper.DecodeState) (GNBIdentity, aper.Snapshot) {
	return &v.capture
}
func BridgeGNBIdentityValueCodecFieldCompare(v *GNBIdentityValueCodec) *func(GNBIdentity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGNBIdentityValueCodecFieldContext(v *GNBIdentityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGNBIdentityValueCodecFieldDecode(v *GNBIdentityValueCodec) *func([]byte, aper.DecodeState) (GNBIdentity, error) {
	return &v.decode
}
func BridgeGNBIdentityValueCodecFieldEncode(v *GNBIdentityValueCodec) *func(GNBIdentity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGNBIdentityValueCodecFieldPath(v *GNBIdentityValueCodec) *aper.Path { return &v.path }
func BridgeGNBIdentityValueCodecMethodEncodeBudgetValue(v GNBIdentityValueCodec, a0 GNBIdentity, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGNBIdentityValueCodecMethodEncodeChanged(v GNBIdentityValueCodec, a0 GNBIdentity, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGNBMethodMarshalAPERBudget(v *GNB, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGNBMethodMarshalAPERBudgetValue(v *GNB, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGNBMethodMarshalAPERChanged(v *GNB, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGNBMethodMarshalAPERChangedValue(v *GNB, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGNBMethodMarshalAPERLegacy(v *GNB) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeGNBMethodMarshalAPERNewValue(v *GNB, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGNBMethodMarshalAPERPlanned(v *GNB, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGNBMethodMarshalAPERTo(v *GNB, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGNBMethodUnmarshalAPERFrom(v *GNB, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGNBMethodUnmarshalAPERLegacy(v *GNB, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeGNBMethodUnmarshalAPERWithOptions(v *GNB, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGNBValueCodecFieldCapture(v *GNBValueCodec) *func(GNB, aper.DecodeState) (GNB, aper.Snapshot) {
	return &v.capture
}
func BridgeGNBValueCodecFieldCompare(v *GNBValueCodec) *func(GNB, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGNBValueCodecFieldContext(v *GNBValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeGNBValueCodecFieldDecode(v *GNBValueCodec) *func([]byte, aper.DecodeState) (GNB, error) {
	return &v.decode
}
func BridgeGNBValueCodecFieldEncode(v *GNBValueCodec) *func(GNB, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGNBValueCodecFieldPath(v *GNBValueCodec) *aper.Path { return &v.path }
func BridgeGNBValueCodecMethodEncodeBudgetValue(v GNBValueCodec, a0 GNB, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGNBValueCodecMethodEncodeChanged(v GNBValueCodec, a0 GNB, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGUMMEIAPERValueFieldContext(v *GUMMEIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeGUMMEIAPERValueFieldReceived(v *GUMMEIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeGUMMEIAPERValueFieldReplay(v *GUMMEIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeGUMMEIAPERValueFieldWithoutReplay(v *GUMMEIAPERValue) *bool             { return &v.withoutReplay }
func BridgeGUMMEIFieldExtCount(v *GUMMEI) *int64                                   { return &v.extCount }
func BridgeGUMMEIFieldExtData(v *GUMMEI) *[][]byte                                 { return &v.extData }
func BridgeGUMMEIFieldExtOrigin(v *GUMMEI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeGUMMEIFieldExtPresent(v *GUMMEI) *[]bool                                { return &v.extPresent }
func BridgeGUMMEIFieldExtWire(v *GUMMEI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeGUMMEIFieldIEExtensionsIndef(v *GUMMEI) *bool                           { return &v.iEExtensionsIndef }
func BridgeGUMMEIFieldPerExtPadding(v *GUMMEI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeGUMMEIFieldPerPadding(v *GUMMEI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeGUMMEIFieldReceived(v *GUMMEI) *bool                                    { return &v.received }
func BridgeGUMMEIFieldReceivedAbsolute(v *GUMMEI) *bool                            { return &v.receivedAbsolute }
func BridgeGUMMEIFieldReceivedBytes(v *GUMMEI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeGUMMEIFieldReceivedLocation(v *GUMMEI) *aper.Location                   { return &v.receivedLocation }
func BridgeGUMMEIFieldReplay(v *GUMMEI) *aper.Snapshot                             { return &v.replay }
func BridgeGUMMEIFieldStream(v *GUMMEI) *aper.WireSpan                             { return &v.stream }
func BridgeGUMMEIFieldWithoutReplay(v *GUMMEI) *bool                               { return &v.withoutReplay }
func BridgeGUMMEIListAPERValueFieldContext(v *GUMMEIListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEIListAPERValueFieldReceived(v *GUMMEIListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGUMMEIListAPERValueFieldReplay(v *GUMMEIListAPERValue) *aper.Snapshot { return &v.replay }
func BridgeGUMMEIListAPERValueFieldWithoutReplay(v *GUMMEIListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGUMMEIListValueCodecFieldCapture(v *GUMMEIListValueCodec) *func(GUMMEIList, aper.DecodeState) (GUMMEIList, aper.Snapshot) {
	return &v.capture
}
func BridgeGUMMEIListValueCodecFieldCompare(v *GUMMEIListValueCodec) *func(GUMMEIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGUMMEIListValueCodecFieldContext(v *GUMMEIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEIListValueCodecFieldDecode(v *GUMMEIListValueCodec) *func([]byte, aper.DecodeState) (GUMMEIList, error) {
	return &v.decode
}
func BridgeGUMMEIListValueCodecFieldEncode(v *GUMMEIListValueCodec) *func(GUMMEIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGUMMEIListValueCodecFieldPath(v *GUMMEIListValueCodec) *aper.Path { return &v.path }
func BridgeGUMMEIListValueCodecMethodEncodeBudgetValue(v GUMMEIListValueCodec, a0 GUMMEIList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGUMMEIListValueCodecMethodEncodeChanged(v GUMMEIListValueCodec, a0 GUMMEIList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGUMMEIMethodMarshalAPERBudget(v *GUMMEI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGUMMEIMethodMarshalAPERBudgetValue(v *GUMMEI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGUMMEIMethodMarshalAPERChanged(v *GUMMEI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGUMMEIMethodMarshalAPERChangedValue(v *GUMMEI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGUMMEIMethodMarshalAPERLegacy(v *GUMMEI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeGUMMEIMethodMarshalAPERNewValue(v *GUMMEI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGUMMEIMethodMarshalAPERPlanned(v *GUMMEI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGUMMEIMethodMarshalAPERTo(v *GUMMEI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGUMMEIMethodUnmarshalAPERFrom(v *GUMMEI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGUMMEIMethodUnmarshalAPERLegacy(v *GUMMEI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGUMMEIMethodUnmarshalAPERWithOptions(v *GUMMEI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGUMMEIValueCodecFieldCapture(v *GUMMEIValueCodec) *func(GUMMEI, aper.DecodeState) (GUMMEI, aper.Snapshot) {
	return &v.capture
}
func BridgeGUMMEIValueCodecFieldCompare(v *GUMMEIValueCodec) *func(GUMMEI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGUMMEIValueCodecFieldContext(v *GUMMEIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEIValueCodecFieldDecode(v *GUMMEIValueCodec) *func([]byte, aper.DecodeState) (GUMMEI, error) {
	return &v.decode
}
func BridgeGUMMEIValueCodecFieldEncode(v *GUMMEIValueCodec) *func(GUMMEI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGUMMEIValueCodecFieldPath(v *GUMMEIValueCodec) *aper.Path { return &v.path }
func BridgeGUMMEIValueCodecMethodEncodeBudgetValue(v GUMMEIValueCodec, a0 GUMMEI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGUMMEIValueCodecMethodEncodeChanged(v GUMMEIValueCodec, a0 GUMMEI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGlobalENBIDAPERValueFieldContext(v *GlobalENBIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalENBIDAPERValueFieldReceived(v *GlobalENBIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGlobalENBIDAPERValueFieldReplay(v *GlobalENBIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeGlobalENBIDAPERValueFieldWithoutReplay(v *GlobalENBIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGlobalENBIDFieldExtCount(v *GlobalENBID) *int64                { return &v.extCount }
func BridgeGlobalENBIDFieldExtData(v *GlobalENBID) *[][]byte              { return &v.extData }
func BridgeGlobalENBIDFieldExtOrigin(v *GlobalENBID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeGlobalENBIDFieldExtPresent(v *GlobalENBID) *[]bool             { return &v.extPresent }
func BridgeGlobalENBIDFieldExtWire(v *GlobalENBID) *[]aper.WireSpan       { return &v.extWire }
func BridgeGlobalENBIDFieldIEExtensionsIndef(v *GlobalENBID) *bool        { return &v.iEExtensionsIndef }
func BridgeGlobalENBIDFieldPerExtPadding(v *GlobalENBID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeGlobalENBIDFieldPerPadding(v *GlobalENBID) *aper.FinalPadding { return &v.perPadding }
func BridgeGlobalENBIDFieldReceived(v *GlobalENBID) *bool                { return &v.received }
func BridgeGlobalENBIDFieldReceivedAbsolute(v *GlobalENBID) *bool        { return &v.receivedAbsolute }
func BridgeGlobalENBIDFieldReceivedBytes(v *GlobalENBID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeGlobalENBIDFieldReceivedLocation(v *GlobalENBID) *aper.Location {
	return &v.receivedLocation
}
func BridgeGlobalENBIDFieldReplay(v *GlobalENBID) *aper.Snapshot { return &v.replay }
func BridgeGlobalENBIDFieldStream(v *GlobalENBID) *aper.WireSpan { return &v.stream }
func BridgeGlobalENBIDFieldWithoutReplay(v *GlobalENBID) *bool   { return &v.withoutReplay }
func BridgeGlobalENBIDMethodMarshalAPERBudget(v *GlobalENBID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGlobalENBIDMethodMarshalAPERBudgetValue(v *GlobalENBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGlobalENBIDMethodMarshalAPERChanged(v *GlobalENBID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGlobalENBIDMethodMarshalAPERChangedValue(v *GlobalENBID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGlobalENBIDMethodMarshalAPERLegacy(v *GlobalENBID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGlobalENBIDMethodMarshalAPERNewValue(v *GlobalENBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGlobalENBIDMethodMarshalAPERPlanned(v *GlobalENBID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGlobalENBIDMethodMarshalAPERTo(v *GlobalENBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalENBIDMethodUnmarshalAPERFrom(v *GlobalENBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalENBIDMethodUnmarshalAPERLegacy(v *GlobalENBID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGlobalENBIDMethodUnmarshalAPERWithOptions(v *GlobalENBID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGlobalENBIDValueCodecFieldCapture(v *GlobalENBIDValueCodec) *func(GlobalENBID, aper.DecodeState) (GlobalENBID, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalENBIDValueCodecFieldCompare(v *GlobalENBIDValueCodec) *func(GlobalENBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalENBIDValueCodecFieldContext(v *GlobalENBIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalENBIDValueCodecFieldDecode(v *GlobalENBIDValueCodec) *func([]byte, aper.DecodeState) (GlobalENBID, error) {
	return &v.decode
}
func BridgeGlobalENBIDValueCodecFieldEncode(v *GlobalENBIDValueCodec) *func(GlobalENBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalENBIDValueCodecFieldPath(v *GlobalENBIDValueCodec) *aper.Path { return &v.path }
func BridgeGlobalENBIDValueCodecMethodEncodeBudgetValue(v GlobalENBIDValueCodec, a0 GlobalENBID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGlobalENBIDValueCodecMethodEncodeChanged(v GlobalENBIDValueCodec, a0 GlobalENBID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGlobalEnGNBIDAPERValueFieldContext(v *GlobalEnGNBIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalEnGNBIDAPERValueFieldReceived(v *GlobalEnGNBIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGlobalEnGNBIDAPERValueFieldReplay(v *GlobalEnGNBIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeGlobalEnGNBIDAPERValueFieldWithoutReplay(v *GlobalEnGNBIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGlobalEnGNBIDFieldExtCount(v *GlobalEnGNBID) *int64                { return &v.extCount }
func BridgeGlobalEnGNBIDFieldExtData(v *GlobalEnGNBID) *[][]byte              { return &v.extData }
func BridgeGlobalEnGNBIDFieldExtOrigin(v *GlobalEnGNBID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeGlobalEnGNBIDFieldExtPresent(v *GlobalEnGNBID) *[]bool             { return &v.extPresent }
func BridgeGlobalEnGNBIDFieldExtWire(v *GlobalEnGNBID) *[]aper.WireSpan       { return &v.extWire }
func BridgeGlobalEnGNBIDFieldIEExtensionsIndef(v *GlobalEnGNBID) *bool        { return &v.iEExtensionsIndef }
func BridgeGlobalEnGNBIDFieldPerExtPadding(v *GlobalEnGNBID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeGlobalEnGNBIDFieldPerPadding(v *GlobalEnGNBID) *aper.FinalPadding { return &v.perPadding }
func BridgeGlobalEnGNBIDFieldReceived(v *GlobalEnGNBID) *bool                { return &v.received }
func BridgeGlobalEnGNBIDFieldReceivedAbsolute(v *GlobalEnGNBID) *bool        { return &v.receivedAbsolute }
func BridgeGlobalEnGNBIDFieldReceivedBytes(v *GlobalEnGNBID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeGlobalEnGNBIDFieldReceivedLocation(v *GlobalEnGNBID) *aper.Location {
	return &v.receivedLocation
}
func BridgeGlobalEnGNBIDFieldReplay(v *GlobalEnGNBID) *aper.Snapshot { return &v.replay }
func BridgeGlobalEnGNBIDFieldStream(v *GlobalEnGNBID) *aper.WireSpan { return &v.stream }
func BridgeGlobalEnGNBIDFieldWithoutReplay(v *GlobalEnGNBID) *bool   { return &v.withoutReplay }
func BridgeGlobalEnGNBIDMethodMarshalAPERBudget(v *GlobalEnGNBID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERBudgetValue(v *GlobalEnGNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERChanged(v *GlobalEnGNBID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERChangedValue(v *GlobalEnGNBID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERLegacy(v *GlobalEnGNBID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGlobalEnGNBIDMethodMarshalAPERNewValue(v *GlobalEnGNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERPlanned(v *GlobalEnGNBID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGlobalEnGNBIDMethodMarshalAPERTo(v *GlobalEnGNBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalEnGNBIDMethodUnmarshalAPERFrom(v *GlobalEnGNBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalEnGNBIDMethodUnmarshalAPERLegacy(v *GlobalEnGNBID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGlobalEnGNBIDMethodUnmarshalAPERWithOptions(v *GlobalEnGNBID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGlobalEnGNBIDValueCodecFieldCapture(v *GlobalEnGNBIDValueCodec) *func(GlobalEnGNBID, aper.DecodeState) (GlobalEnGNBID, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalEnGNBIDValueCodecFieldCompare(v *GlobalEnGNBIDValueCodec) *func(GlobalEnGNBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalEnGNBIDValueCodecFieldContext(v *GlobalEnGNBIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalEnGNBIDValueCodecFieldDecode(v *GlobalEnGNBIDValueCodec) *func([]byte, aper.DecodeState) (GlobalEnGNBID, error) {
	return &v.decode
}
func BridgeGlobalEnGNBIDValueCodecFieldEncode(v *GlobalEnGNBIDValueCodec) *func(GlobalEnGNBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalEnGNBIDValueCodecFieldPath(v *GlobalEnGNBIDValueCodec) *aper.Path { return &v.path }
func BridgeGlobalEnGNBIDValueCodecMethodEncodeBudgetValue(v GlobalEnGNBIDValueCodec, a0 GlobalEnGNBID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGlobalEnGNBIDValueCodecMethodEncodeChanged(v GlobalEnGNBIDValueCodec, a0 GlobalEnGNBID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGlobalGNBIDAPERValueFieldContext(v *GlobalGNBIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalGNBIDAPERValueFieldReceived(v *GlobalGNBIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGlobalGNBIDAPERValueFieldReplay(v *GlobalGNBIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeGlobalGNBIDAPERValueFieldWithoutReplay(v *GlobalGNBIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGlobalGNBIDFieldExtCount(v *GlobalGNBID) *int64                { return &v.extCount }
func BridgeGlobalGNBIDFieldExtData(v *GlobalGNBID) *[][]byte              { return &v.extData }
func BridgeGlobalGNBIDFieldExtOrigin(v *GlobalGNBID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeGlobalGNBIDFieldExtPresent(v *GlobalGNBID) *[]bool             { return &v.extPresent }
func BridgeGlobalGNBIDFieldExtWire(v *GlobalGNBID) *[]aper.WireSpan       { return &v.extWire }
func BridgeGlobalGNBIDFieldIEExtensionsIndef(v *GlobalGNBID) *bool        { return &v.iEExtensionsIndef }
func BridgeGlobalGNBIDFieldPerExtPadding(v *GlobalGNBID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeGlobalGNBIDFieldPerPadding(v *GlobalGNBID) *aper.FinalPadding { return &v.perPadding }
func BridgeGlobalGNBIDFieldReceived(v *GlobalGNBID) *bool                { return &v.received }
func BridgeGlobalGNBIDFieldReceivedAbsolute(v *GlobalGNBID) *bool        { return &v.receivedAbsolute }
func BridgeGlobalGNBIDFieldReceivedBytes(v *GlobalGNBID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeGlobalGNBIDFieldReceivedLocation(v *GlobalGNBID) *aper.Location {
	return &v.receivedLocation
}
func BridgeGlobalGNBIDFieldReplay(v *GlobalGNBID) *aper.Snapshot { return &v.replay }
func BridgeGlobalGNBIDFieldStream(v *GlobalGNBID) *aper.WireSpan { return &v.stream }
func BridgeGlobalGNBIDFieldWithoutReplay(v *GlobalGNBID) *bool   { return &v.withoutReplay }
func BridgeGlobalGNBIDMethodMarshalAPERBudget(v *GlobalGNBID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGlobalGNBIDMethodMarshalAPERBudgetValue(v *GlobalGNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGlobalGNBIDMethodMarshalAPERChanged(v *GlobalGNBID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGlobalGNBIDMethodMarshalAPERChangedValue(v *GlobalGNBID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGlobalGNBIDMethodMarshalAPERLegacy(v *GlobalGNBID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGlobalGNBIDMethodMarshalAPERNewValue(v *GlobalGNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGlobalGNBIDMethodMarshalAPERPlanned(v *GlobalGNBID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGlobalGNBIDMethodMarshalAPERTo(v *GlobalGNBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalGNBIDMethodUnmarshalAPERFrom(v *GlobalGNBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalGNBIDMethodUnmarshalAPERLegacy(v *GlobalGNBID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGlobalGNBIDMethodUnmarshalAPERWithOptions(v *GlobalGNBID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGlobalGNBIDValueCodecFieldCapture(v *GlobalGNBIDValueCodec) *func(GlobalGNBID, aper.DecodeState) (GlobalGNBID, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalGNBIDValueCodecFieldCompare(v *GlobalGNBIDValueCodec) *func(GlobalGNBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalGNBIDValueCodecFieldContext(v *GlobalGNBIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalGNBIDValueCodecFieldDecode(v *GlobalGNBIDValueCodec) *func([]byte, aper.DecodeState) (GlobalGNBID, error) {
	return &v.decode
}
func BridgeGlobalGNBIDValueCodecFieldEncode(v *GlobalGNBIDValueCodec) *func(GlobalGNBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalGNBIDValueCodecFieldPath(v *GlobalGNBIDValueCodec) *aper.Path { return &v.path }
func BridgeGlobalGNBIDValueCodecMethodEncodeBudgetValue(v GlobalGNBIDValueCodec, a0 GlobalGNBID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGlobalGNBIDValueCodecMethodEncodeChanged(v GlobalGNBIDValueCodec, a0 GlobalGNBID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelCauseIEBindingFieldCodec(v *HandoverCancelCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeHandoverCancelCauseIEBindingFieldGet(v *HandoverCancelCauseIEBinding) *func(*HandoverCancelIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeHandoverCancelCauseIEBindingFieldInfo(v *HandoverCancelCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelCauseIEBindingFieldInject(v *HandoverCancelCauseIEBinding) *func(s14.Cause) HandoverCancelIEValue {
	return &v.inject
}
func BridgeHandoverCancelENBUES1APIDIEBindingFieldCodec(v *HandoverCancelENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCancelENBUES1APIDIEBindingFieldGet(v *HandoverCancelENBUES1APIDIEBinding) *func(*HandoverCancelIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCancelENBUES1APIDIEBindingFieldInfo(v *HandoverCancelENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelENBUES1APIDIEBindingFieldInject(v *HandoverCancelENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverCancelIEValue {
	return &v.inject
}
func BridgeHandoverCancelIEContainerAPERValueFieldContext(v *HandoverCancelIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEContainerAPERValueFieldReceived(v *HandoverCancelIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEContainerAPERValueFieldReplay(v *HandoverCancelIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEContainerAPERValueFieldWithoutReplay(v *HandoverCancelIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEContainerValueCodecFieldCapture(v *HandoverCancelIEContainerValueCodec) *func(HandoverCancelIEContainer, aper.DecodeState) (HandoverCancelIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelIEContainerValueCodecFieldCompare(v *HandoverCancelIEContainerValueCodec) *func(HandoverCancelIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelIEContainerValueCodecFieldContext(v *HandoverCancelIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEContainerValueCodecFieldDecode(v *HandoverCancelIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelIEContainer, error) {
	return &v.decode
}
func BridgeHandoverCancelIEContainerValueCodecFieldEncode(v *HandoverCancelIEContainerValueCodec) *func(HandoverCancelIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelIEContainerValueCodecFieldPath(v *HandoverCancelIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelIEContainerValueCodecMethodEncodeBudgetValue(v HandoverCancelIEContainerValueCodec, a0 HandoverCancelIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelIEContainerValueCodecMethodEncodeChanged(v HandoverCancelIEContainerValueCodec, a0 HandoverCancelIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelIEFieldAPERValueFieldContext(v *HandoverCancelIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEFieldAPERValueFieldReceived(v *HandoverCancelIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEFieldAPERValueFieldReplay(v *HandoverCancelIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEFieldAPERValueFieldWithoutReplay(v *HandoverCancelIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEFieldFieldReceived(v *HandoverCancelIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverCancelIEFieldFieldReplay(v *HandoverCancelIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEFieldFieldStream(v *HandoverCancelIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverCancelIEFieldFieldWithoutReplay(v *HandoverCancelIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEFieldMethodMarshalAPERTo(v *HandoverCancelIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverCancelIEFieldMethodUnmarshalAPERFrom(v *HandoverCancelIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverCancelIEFieldValueCodecFieldCapture(v *HandoverCancelIEFieldValueCodec) *func(HandoverCancelIEField, aper.DecodeState) (HandoverCancelIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelIEFieldValueCodecFieldCompare(v *HandoverCancelIEFieldValueCodec) *func(HandoverCancelIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelIEFieldValueCodecFieldContext(v *HandoverCancelIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEFieldValueCodecFieldDecode(v *HandoverCancelIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelIEField, error) {
	return &v.decode
}
func BridgeHandoverCancelIEFieldValueCodecFieldEncode(v *HandoverCancelIEFieldValueCodec) *func(HandoverCancelIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelIEFieldValueCodecFieldPath(v *HandoverCancelIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelIEFieldValueCodecMethodEncodeBudgetValue(v HandoverCancelIEFieldValueCodec, a0 HandoverCancelIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelIEFieldValueCodecMethodEncodeChanged(v HandoverCancelIEFieldValueCodec, a0 HandoverCancelIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelIETableMethodInfoCause(v HandoverCancelIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeHandoverCancelIETableMethodInfoENBUES1APID(v HandoverCancelIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverCancelIETableMethodInfoMMEUES1APID(v HandoverCancelIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverCancelIEValueERABIEContainerListAPERValueFieldContext(v *HandoverCancelIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverCancelIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverCancelIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverCancelIEValueERABIEContainerListValueCodec) *func(HandoverCancelIEValueERABIEContainerList, aper.DecodeState) (HandoverCancelIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverCancelIEValueERABIEContainerListValueCodec) *func(HandoverCancelIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldContext(v *HandoverCancelIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverCancelIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverCancelIEValueERABIEContainerListValueCodec) *func(HandoverCancelIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecFieldPath(v *HandoverCancelIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelIEValueERABIEContainerListValueCodec, a0 HandoverCancelIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelIEValueERABIEContainerListValueCodec, a0 HandoverCancelIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelIEValueFieldId(v *HandoverCancelIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverCancelIEValueFieldIsOpaque(v *HandoverCancelIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverCancelIEValueFieldOpaque(v *HandoverCancelIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverCancelIEValueFieldReceived(v *HandoverCancelIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEValueFieldReplay(v *HandoverCancelIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEValueFieldRowCause(v *HandoverCancelIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeHandoverCancelIEValueFieldRowENBUES1APID(v *HandoverCancelIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverCancelIEValueFieldRowMMEUES1APID(v *HandoverCancelIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverCancelIEValueMethodCaptureSemantics(v HandoverCancelIEValue, a0 aper.SemanticCapture) HandoverCancelIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverCancelIEValueMethodCompareSemantics(v HandoverCancelIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverCancelIEValueMethodDecode(v HandoverCancelIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverCancelIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverCancelIEValueMethodEncode(v HandoverCancelIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverCancelIEValueMethodEncodeFresh(v HandoverCancelIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverCancelIEValueMethodMatchesID(v HandoverCancelIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverCancelIEValueMethodReason(v HandoverCancelIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverCancelIEValueMethodRule(v HandoverCancelIEValue) aper.SourceRule { return v.rule() }
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverCancelIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCancelIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverCancelIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverCancelIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverCancelIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverCancelIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverCancelIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverCancelIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverCancelIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolIEContainerList, aper.DecodeState) (HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverCancelIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *func(HandoverCancelIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverCancelIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverCancelIEValueProtocolIEContainerListValueCodec, a0 HandoverCancelIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverCancelIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverCancelIEValueProtocolIEContainerListValueCodec, a0 HandoverCancelIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverCancelMMEUES1APIDIEBindingFieldCodec(v *HandoverCancelMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverCancelMMEUES1APIDIEBindingFieldGet(v *HandoverCancelMMEUES1APIDIEBinding) *func(*HandoverCancelIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverCancelMMEUES1APIDIEBindingFieldInfo(v *HandoverCancelMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverCancelMMEUES1APIDIEBindingFieldInject(v *HandoverCancelMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverCancelIEValue {
	return &v.inject
}
func BridgeHandoverSuccessAPERValueFieldContext(v *HandoverSuccessAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessAPERValueFieldReceived(v *HandoverSuccessAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverSuccessAPERValueFieldReplay(v *HandoverSuccessAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverSuccessAPERValueFieldWithoutReplay(v *HandoverSuccessAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverSuccessFieldExtCount(v *HandoverSuccess) *int64   { return &v.extCount }
func BridgeHandoverSuccessFieldExtData(v *HandoverSuccess) *[][]byte { return &v.extData }
func BridgeHandoverSuccessFieldExtOrigin(v *HandoverSuccess) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverSuccessFieldExtPresent(v *HandoverSuccess) *[]bool       { return &v.extPresent }
func BridgeHandoverSuccessFieldExtWire(v *HandoverSuccess) *[]aper.WireSpan { return &v.extWire }
func BridgeHandoverSuccessFieldPerExtPadding(v *HandoverSuccess) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverSuccessFieldPerPadding(v *HandoverSuccess) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverSuccessFieldProtocolIEsIndef(v *HandoverSuccess) *bool { return &v.protocolIEsIndef }
func BridgeHandoverSuccessFieldReceived(v *HandoverSuccess) *bool         { return &v.received }
func BridgeHandoverSuccessFieldReceivedAbsolute(v *HandoverSuccess) *bool { return &v.receivedAbsolute }
func BridgeHandoverSuccessFieldReceivedBytes(v *HandoverSuccess) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverSuccessFieldReceivedLocation(v *HandoverSuccess) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverSuccessFieldReplay(v *HandoverSuccess) *aper.Snapshot { return &v.replay }
func BridgeHandoverSuccessFieldStream(v *HandoverSuccess) *aper.WireSpan { return &v.stream }
func BridgeHandoverSuccessFieldWithoutReplay(v *HandoverSuccess) *bool   { return &v.withoutReplay }
func BridgeHandoverSuccessMethodMarshalAPERBudget(v *HandoverSuccess, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverSuccessMethodMarshalAPERBudgetValue(v *HandoverSuccess, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverSuccessMethodMarshalAPERChanged(v *HandoverSuccess, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverSuccessMethodMarshalAPERChangedValue(v *HandoverSuccess, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverSuccessMethodMarshalAPERLegacy(v *HandoverSuccess) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverSuccessMethodMarshalAPERNewValue(v *HandoverSuccess, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverSuccessMethodMarshalAPERPlanned(v *HandoverSuccess, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverSuccessMethodMarshalAPERTo(v *HandoverSuccess, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverSuccessMethodUnmarshalAPERFrom(v *HandoverSuccess, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverSuccessMethodUnmarshalAPERLegacy(v *HandoverSuccess, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverSuccessMethodUnmarshalAPERWithOptions(v *HandoverSuccess, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverSuccessValueCodecFieldCapture(v *HandoverSuccessValueCodec) *func(HandoverSuccess, aper.DecodeState) (HandoverSuccess, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverSuccessValueCodecFieldCompare(v *HandoverSuccessValueCodec) *func(HandoverSuccess, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverSuccessValueCodecFieldContext(v *HandoverSuccessValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverSuccessValueCodecFieldDecode(v *HandoverSuccessValueCodec) *func([]byte, aper.DecodeState) (HandoverSuccess, error) {
	return &v.decode
}
func BridgeHandoverSuccessValueCodecFieldEncode(v *HandoverSuccessValueCodec) *func(HandoverSuccess, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverSuccessValueCodecFieldPath(v *HandoverSuccessValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverSuccessValueCodecMethodEncodeBudgetValue(v HandoverSuccessValueCodec, a0 HandoverSuccess, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverSuccessValueCodecMethodEncodeChanged(v HandoverSuccessValueCodec, a0 HandoverSuccess, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeIEsECGIListAPERValueFieldContext(v *IEsECGIListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIEsECGIListAPERValueFieldReceived(v *IEsECGIListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeIEsECGIListAPERValueFieldReplay(v *IEsECGIListAPERValue) *aper.Snapshot { return &v.replay }
func BridgeIEsECGIListAPERValueFieldWithoutReplay(v *IEsECGIListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeIEsECGIListValueCodecFieldCapture(v *IEsECGIListValueCodec) *func(IEsECGIList, aper.DecodeState) (IEsECGIList, aper.Snapshot) {
	return &v.capture
}
func BridgeIEsECGIListValueCodecFieldCompare(v *IEsECGIListValueCodec) *func(IEsECGIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIEsECGIListValueCodecFieldContext(v *IEsECGIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIEsECGIListValueCodecFieldDecode(v *IEsECGIListValueCodec) *func([]byte, aper.DecodeState) (IEsECGIList, error) {
	return &v.decode
}
func BridgeIEsECGIListValueCodecFieldEncode(v *IEsECGIListValueCodec) *func(IEsECGIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIEsECGIListValueCodecFieldPath(v *IEsECGIListValueCodec) *aper.Path { return &v.path }
func BridgeIEsECGIListValueCodecMethodEncodeBudgetValue(v IEsECGIListValueCodec, a0 IEsECGIList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeIEsECGIListValueCodecMethodEncodeChanged(v IEsECGIListValueCodec, a0 IEsECGIList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeIRATCellIDAPERValueFieldContext(v *IRATCellIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIRATCellIDAPERValueFieldReceived(v *IRATCellIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeIRATCellIDAPERValueFieldReplay(v *IRATCellIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeIRATCellIDAPERValueFieldWithoutReplay(v *IRATCellIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeIRATCellIDFieldPerOpenTypePadding(v *IRATCellID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeIRATCellIDFieldPerPadding(v *IRATCellID) *aper.CompletePadding { return &v.perPadding }
func BridgeIRATCellIDFieldReceived(v *IRATCellID) *bool                   { return &v.received }
func BridgeIRATCellIDFieldReceivedAbsolute(v *IRATCellID) *bool           { return &v.receivedAbsolute }
func BridgeIRATCellIDFieldReceivedBytes(v *IRATCellID) *aper.WireSpan     { return &v.receivedBytes }
func BridgeIRATCellIDFieldReceivedLocation(v *IRATCellID) *aper.Location  { return &v.receivedLocation }
func BridgeIRATCellIDFieldReplay(v *IRATCellID) *aper.Snapshot            { return &v.replay }
func BridgeIRATCellIDFieldStream(v *IRATCellID) *aper.WireSpan            { return &v.stream }
func BridgeIRATCellIDFieldWithoutReplay(v *IRATCellID) *bool              { return &v.withoutReplay }
func BridgeIRATCellIDMethodMarshalAPERBudget(v *IRATCellID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeIRATCellIDMethodMarshalAPERBudgetValue(v *IRATCellID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeIRATCellIDMethodMarshalAPERChanged(v *IRATCellID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeIRATCellIDMethodMarshalAPERChangedValue(v *IRATCellID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeIRATCellIDMethodMarshalAPERLegacy(v *IRATCellID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeIRATCellIDMethodMarshalAPERNewValue(v *IRATCellID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeIRATCellIDMethodMarshalAPERPlanned(v *IRATCellID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeIRATCellIDMethodMarshalAPERTo(v *IRATCellID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeIRATCellIDMethodUnmarshalAPERFrom(v *IRATCellID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeIRATCellIDMethodUnmarshalAPERLegacy(v *IRATCellID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeIRATCellIDMethodUnmarshalAPERWithOptions(v *IRATCellID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeIRATCellIDValueCodecFieldCapture(v *IRATCellIDValueCodec) *func(IRATCellID, aper.DecodeState) (IRATCellID, aper.Snapshot) {
	return &v.capture
}
func BridgeIRATCellIDValueCodecFieldCompare(v *IRATCellIDValueCodec) *func(IRATCellID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIRATCellIDValueCodecFieldContext(v *IRATCellIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIRATCellIDValueCodecFieldDecode(v *IRATCellIDValueCodec) *func([]byte, aper.DecodeState) (IRATCellID, error) {
	return &v.decode
}
func BridgeIRATCellIDValueCodecFieldEncode(v *IRATCellIDValueCodec) *func(IRATCellID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIRATCellIDValueCodecFieldPath(v *IRATCellIDValueCodec) *aper.Path { return &v.path }
func BridgeIRATCellIDValueCodecMethodEncodeBudgetValue(v IRATCellIDValueCodec, a0 IRATCellID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeIRATCellIDValueCodecMethodEncodeChanged(v IRATCellIDValueCodec, a0 IRATCellID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterSystemMeasurementItemAPERValueFieldContext(v *InterSystemMeasurementItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementItemAPERValueFieldReceived(v *InterSystemMeasurementItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterSystemMeasurementItemAPERValueFieldReplay(v *InterSystemMeasurementItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementItemAPERValueFieldWithoutReplay(v *InterSystemMeasurementItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementItemFieldIEExtensionsIndef(v *InterSystemMeasurementItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeInterSystemMeasurementItemFieldPerPadding(v *InterSystemMeasurementItem) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterSystemMeasurementItemFieldReceived(v *InterSystemMeasurementItem) *bool {
	return &v.received
}
func BridgeInterSystemMeasurementItemFieldReceivedAbsolute(v *InterSystemMeasurementItem) *bool {
	return &v.receivedAbsolute
}
func BridgeInterSystemMeasurementItemFieldReceivedBytes(v *InterSystemMeasurementItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterSystemMeasurementItemFieldReceivedLocation(v *InterSystemMeasurementItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeInterSystemMeasurementItemFieldReplay(v *InterSystemMeasurementItem) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementItemFieldStream(v *InterSystemMeasurementItem) *aper.WireSpan {
	return &v.stream
}
func BridgeInterSystemMeasurementItemFieldWithoutReplay(v *InterSystemMeasurementItem) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERBudget(v *InterSystemMeasurementItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERBudgetValue(v *InterSystemMeasurementItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERChanged(v *InterSystemMeasurementItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERChangedValue(v *InterSystemMeasurementItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERLegacy(v *InterSystemMeasurementItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERNewValue(v *InterSystemMeasurementItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERPlanned(v *InterSystemMeasurementItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInterSystemMeasurementItemMethodMarshalAPERTo(v *InterSystemMeasurementItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterSystemMeasurementItemMethodUnmarshalAPERFrom(v *InterSystemMeasurementItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterSystemMeasurementItemMethodUnmarshalAPERLegacy(v *InterSystemMeasurementItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterSystemMeasurementItemMethodUnmarshalAPERWithOptions(v *InterSystemMeasurementItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterSystemMeasurementItemValueCodecFieldCapture(v *InterSystemMeasurementItemValueCodec) *func(InterSystemMeasurementItem, aper.DecodeState) (InterSystemMeasurementItem, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementItemValueCodecFieldCompare(v *InterSystemMeasurementItemValueCodec) *func(InterSystemMeasurementItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementItemValueCodecFieldContext(v *InterSystemMeasurementItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementItemValueCodecFieldDecode(v *InterSystemMeasurementItemValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementItem, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementItemValueCodecFieldEncode(v *InterSystemMeasurementItemValueCodec) *func(InterSystemMeasurementItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementItemValueCodecFieldPath(v *InterSystemMeasurementItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementItemValueCodecMethodEncodeBudgetValue(v InterSystemMeasurementItemValueCodec, a0 InterSystemMeasurementItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementItemValueCodecMethodEncodeChanged(v InterSystemMeasurementItemValueCodec, a0 InterSystemMeasurementItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterSystemMeasurementListAPERValueFieldContext(v *InterSystemMeasurementListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementListAPERValueFieldReceived(v *InterSystemMeasurementListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterSystemMeasurementListAPERValueFieldReplay(v *InterSystemMeasurementListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemMeasurementListAPERValueFieldWithoutReplay(v *InterSystemMeasurementListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemMeasurementListValueCodecFieldCapture(v *InterSystemMeasurementListValueCodec) *func(InterSystemMeasurementList, aper.DecodeState) (InterSystemMeasurementList, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemMeasurementListValueCodecFieldCompare(v *InterSystemMeasurementListValueCodec) *func(InterSystemMeasurementList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemMeasurementListValueCodecFieldContext(v *InterSystemMeasurementListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemMeasurementListValueCodecFieldDecode(v *InterSystemMeasurementListValueCodec) *func([]byte, aper.DecodeState) (InterSystemMeasurementList, error) {
	return &v.decode
}
func BridgeInterSystemMeasurementListValueCodecFieldEncode(v *InterSystemMeasurementListValueCodec) *func(InterSystemMeasurementList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemMeasurementListValueCodecFieldPath(v *InterSystemMeasurementListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemMeasurementListValueCodecMethodEncodeBudgetValue(v InterSystemMeasurementListValueCodec, a0 InterSystemMeasurementList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInterSystemMeasurementListValueCodecMethodEncodeChanged(v InterSystemMeasurementListValueCodec, a0 InterSystemMeasurementList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLAIAPERValueFieldContext(v *LAIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeLAIAPERValueFieldReceived(v *LAIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeLAIAPERValueFieldReplay(v *LAIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeLAIAPERValueFieldWithoutReplay(v *LAIAPERValue) *bool             { return &v.withoutReplay }
func BridgeLAIFieldExtCount(v *LAI) *int64                                   { return &v.extCount }
func BridgeLAIFieldExtData(v *LAI) *[][]byte                                 { return &v.extData }
func BridgeLAIFieldExtOrigin(v *LAI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeLAIFieldExtPresent(v *LAI) *[]bool                                { return &v.extPresent }
func BridgeLAIFieldExtWire(v *LAI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeLAIFieldIEExtensionsIndef(v *LAI) *bool                           { return &v.iEExtensionsIndef }
func BridgeLAIFieldPerExtPadding(v *LAI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeLAIFieldPerPadding(v *LAI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeLAIFieldReceived(v *LAI) *bool                                    { return &v.received }
func BridgeLAIFieldReceivedAbsolute(v *LAI) *bool                            { return &v.receivedAbsolute }
func BridgeLAIFieldReceivedBytes(v *LAI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeLAIFieldReceivedLocation(v *LAI) *aper.Location                   { return &v.receivedLocation }
func BridgeLAIFieldReplay(v *LAI) *aper.Snapshot                             { return &v.replay }
func BridgeLAIFieldStream(v *LAI) *aper.WireSpan                             { return &v.stream }
func BridgeLAIFieldWithoutReplay(v *LAI) *bool                               { return &v.withoutReplay }
func BridgeLAIMethodMarshalAPERBudget(v *LAI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLAIMethodMarshalAPERBudgetValue(v *LAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLAIMethodMarshalAPERChanged(v *LAI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLAIMethodMarshalAPERChangedValue(v *LAI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLAIMethodMarshalAPERLegacy(v *LAI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeLAIMethodMarshalAPERNewValue(v *LAI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLAIMethodMarshalAPERPlanned(v *LAI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLAIMethodMarshalAPERTo(v *LAI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLAIMethodUnmarshalAPERFrom(v *LAI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLAIMethodUnmarshalAPERLegacy(v *LAI, a0 []byte) error { return v.unmarshalAPERLegacy(a0) }
func BridgeLAIMethodUnmarshalAPERWithOptions(v *LAI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLAIValueCodecFieldCapture(v *LAIValueCodec) *func(LAI, aper.DecodeState) (LAI, aper.Snapshot) {
	return &v.capture
}
func BridgeLAIValueCodecFieldCompare(v *LAIValueCodec) *func(LAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLAIValueCodecFieldContext(v *LAIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeLAIValueCodecFieldDecode(v *LAIValueCodec) *func([]byte, aper.DecodeState) (LAI, error) {
	return &v.decode
}
func BridgeLAIValueCodecFieldEncode(v *LAIValueCodec) *func(LAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLAIValueCodecFieldPath(v *LAIValueCodec) *aper.Path { return &v.path }
func BridgeLAIValueCodecMethodEncodeBudgetValue(v LAIValueCodec, a0 LAI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLAIValueCodecMethodEncodeChanged(v LAIValueCodec, a0 LAI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLTENTNTAIInformationAPERValueFieldContext(v *LTENTNTAIInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLTENTNTAIInformationAPERValueFieldReceived(v *LTENTNTAIInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLTENTNTAIInformationAPERValueFieldReplay(v *LTENTNTAIInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLTENTNTAIInformationAPERValueFieldWithoutReplay(v *LTENTNTAIInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLTENTNTAIInformationFieldExtCount(v *LTENTNTAIInformation) *int64   { return &v.extCount }
func BridgeLTENTNTAIInformationFieldExtData(v *LTENTNTAIInformation) *[][]byte { return &v.extData }
func BridgeLTENTNTAIInformationFieldExtOrigin(v *LTENTNTAIInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeLTENTNTAIInformationFieldExtPresent(v *LTENTNTAIInformation) *[]bool { return &v.extPresent }
func BridgeLTENTNTAIInformationFieldExtWire(v *LTENTNTAIInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeLTENTNTAIInformationFieldIEExtensionsIndef(v *LTENTNTAIInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeLTENTNTAIInformationFieldPerExtPadding(v *LTENTNTAIInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLTENTNTAIInformationFieldPerPadding(v *LTENTNTAIInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLTENTNTAIInformationFieldReceived(v *LTENTNTAIInformation) *bool { return &v.received }
func BridgeLTENTNTAIInformationFieldReceivedAbsolute(v *LTENTNTAIInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeLTENTNTAIInformationFieldReceivedBytes(v *LTENTNTAIInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLTENTNTAIInformationFieldReceivedLocation(v *LTENTNTAIInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeLTENTNTAIInformationFieldReplay(v *LTENTNTAIInformation) *aper.Snapshot { return &v.replay }
func BridgeLTENTNTAIInformationFieldStream(v *LTENTNTAIInformation) *aper.WireSpan { return &v.stream }
func BridgeLTENTNTAIInformationFieldTACListInLTENTNIndef(v *LTENTNTAIInformation) *bool {
	return &v.tACListInLTENTNIndef
}
func BridgeLTENTNTAIInformationFieldWithoutReplay(v *LTENTNTAIInformation) *bool {
	return &v.withoutReplay
}
func BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v *LTENTNTAIInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERBudgetValue(v *LTENTNTAIInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERChanged(v *LTENTNTAIInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERChangedValue(v *LTENTNTAIInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERLegacy(v *LTENTNTAIInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLTENTNTAIInformationMethodMarshalAPERNewValue(v *LTENTNTAIInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERPlanned(v *LTENTNTAIInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLTENTNTAIInformationMethodMarshalAPERTo(v *LTENTNTAIInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(v *LTENTNTAIInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLTENTNTAIInformationMethodUnmarshalAPERLegacy(v *LTENTNTAIInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLTENTNTAIInformationMethodUnmarshalAPERWithOptions(v *LTENTNTAIInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLTENTNTAIInformationValueCodecFieldCapture(v *LTENTNTAIInformationValueCodec) *func(LTENTNTAIInformation, aper.DecodeState) (LTENTNTAIInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLTENTNTAIInformationValueCodecFieldCompare(v *LTENTNTAIInformationValueCodec) *func(LTENTNTAIInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLTENTNTAIInformationValueCodecFieldContext(v *LTENTNTAIInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLTENTNTAIInformationValueCodecFieldDecode(v *LTENTNTAIInformationValueCodec) *func([]byte, aper.DecodeState) (LTENTNTAIInformation, error) {
	return &v.decode
}
func BridgeLTENTNTAIInformationValueCodecFieldEncode(v *LTENTNTAIInformationValueCodec) *func(LTENTNTAIInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLTENTNTAIInformationValueCodecFieldPath(v *LTENTNTAIInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLTENTNTAIInformationValueCodecMethodEncodeBudgetValue(v LTENTNTAIInformationValueCodec, a0 LTENTNTAIInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLTENTNTAIInformationValueCodecMethodEncodeChanged(v LTENTNTAIInformationValueCodec, a0 LTENTNTAIInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedGERANCellInformationAPERValueFieldContext(v *LastVisitedGERANCellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedGERANCellInformationAPERValueFieldReceived(v *LastVisitedGERANCellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedGERANCellInformationAPERValueFieldReplay(v *LastVisitedGERANCellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedGERANCellInformationAPERValueFieldWithoutReplay(v *LastVisitedGERANCellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedGERANCellInformationFieldPerOpenTypePadding(v *LastVisitedGERANCellInformation) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeLastVisitedGERANCellInformationFieldPerPadding(v *LastVisitedGERANCellInformation) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeLastVisitedGERANCellInformationFieldReceived(v *LastVisitedGERANCellInformation) *bool {
	return &v.received
}
func BridgeLastVisitedGERANCellInformationFieldReceivedAbsolute(v *LastVisitedGERANCellInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeLastVisitedGERANCellInformationFieldReceivedBytes(v *LastVisitedGERANCellInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLastVisitedGERANCellInformationFieldReceivedLocation(v *LastVisitedGERANCellInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeLastVisitedGERANCellInformationFieldReplay(v *LastVisitedGERANCellInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedGERANCellInformationFieldStream(v *LastVisitedGERANCellInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedGERANCellInformationFieldWithoutReplay(v *LastVisitedGERANCellInformation) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudget(v *LastVisitedGERANCellInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudgetValue(v *LastVisitedGERANCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERChanged(v *LastVisitedGERANCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERChangedValue(v *LastVisitedGERANCellInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERLegacy(v *LastVisitedGERANCellInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERNewValue(v *LastVisitedGERANCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERPlanned(v *LastVisitedGERANCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERTo(v *LastVisitedGERANCellInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedGERANCellInformationMethodUnmarshalAPERFrom(v *LastVisitedGERANCellInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedGERANCellInformationMethodUnmarshalAPERLegacy(v *LastVisitedGERANCellInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLastVisitedGERANCellInformationMethodUnmarshalAPERWithOptions(v *LastVisitedGERANCellInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldCapture(v *LastVisitedGERANCellInformationValueCodec) *func(LastVisitedGERANCellInformation, aper.DecodeState) (LastVisitedGERANCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldCompare(v *LastVisitedGERANCellInformationValueCodec) *func(LastVisitedGERANCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldContext(v *LastVisitedGERANCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldDecode(v *LastVisitedGERANCellInformationValueCodec) *func([]byte, aper.DecodeState) (LastVisitedGERANCellInformation, error) {
	return &v.decode
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldEncode(v *LastVisitedGERANCellInformationValueCodec) *func(LastVisitedGERANCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedGERANCellInformationValueCodecFieldPath(v *LastVisitedGERANCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedGERANCellInformationValueCodecMethodEncodeBudgetValue(v LastVisitedGERANCellInformationValueCodec, a0 LastVisitedGERANCellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedGERANCellInformationValueCodecMethodEncodeChanged(v LastVisitedGERANCellInformationValueCodec, a0 LastVisitedGERANCellInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeListeningSubframePatternAPERValueFieldContext(v *ListeningSubframePatternAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeListeningSubframePatternAPERValueFieldReceived(v *ListeningSubframePatternAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeListeningSubframePatternAPERValueFieldReplay(v *ListeningSubframePatternAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeListeningSubframePatternAPERValueFieldWithoutReplay(v *ListeningSubframePatternAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeListeningSubframePatternFieldExtCount(v *ListeningSubframePattern) *int64 {
	return &v.extCount
}
func BridgeListeningSubframePatternFieldExtData(v *ListeningSubframePattern) *[][]byte {
	return &v.extData
}
func BridgeListeningSubframePatternFieldExtOrigin(v *ListeningSubframePattern) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeListeningSubframePatternFieldExtPresent(v *ListeningSubframePattern) *[]bool {
	return &v.extPresent
}
func BridgeListeningSubframePatternFieldExtWire(v *ListeningSubframePattern) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeListeningSubframePatternFieldIEExtensionsIndef(v *ListeningSubframePattern) *bool {
	return &v.iEExtensionsIndef
}
func BridgeListeningSubframePatternFieldPerExtPadding(v *ListeningSubframePattern) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeListeningSubframePatternFieldPerPadding(v *ListeningSubframePattern) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeListeningSubframePatternFieldReceived(v *ListeningSubframePattern) *bool {
	return &v.received
}
func BridgeListeningSubframePatternFieldReceivedAbsolute(v *ListeningSubframePattern) *bool {
	return &v.receivedAbsolute
}
func BridgeListeningSubframePatternFieldReceivedBytes(v *ListeningSubframePattern) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeListeningSubframePatternFieldReceivedLocation(v *ListeningSubframePattern) *aper.Location {
	return &v.receivedLocation
}
func BridgeListeningSubframePatternFieldReplay(v *ListeningSubframePattern) *aper.Snapshot {
	return &v.replay
}
func BridgeListeningSubframePatternFieldStream(v *ListeningSubframePattern) *aper.WireSpan {
	return &v.stream
}
func BridgeListeningSubframePatternFieldWithoutReplay(v *ListeningSubframePattern) *bool {
	return &v.withoutReplay
}
func BridgeListeningSubframePatternMethodMarshalAPERBudget(v *ListeningSubframePattern, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeListeningSubframePatternMethodMarshalAPERBudgetValue(v *ListeningSubframePattern, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeListeningSubframePatternMethodMarshalAPERChanged(v *ListeningSubframePattern, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeListeningSubframePatternMethodMarshalAPERChangedValue(v *ListeningSubframePattern, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeListeningSubframePatternMethodMarshalAPERLegacy(v *ListeningSubframePattern) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeListeningSubframePatternMethodMarshalAPERNewValue(v *ListeningSubframePattern, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeListeningSubframePatternMethodMarshalAPERPlanned(v *ListeningSubframePattern, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeListeningSubframePatternMethodMarshalAPERTo(v *ListeningSubframePattern, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeListeningSubframePatternMethodUnmarshalAPERFrom(v *ListeningSubframePattern, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeListeningSubframePatternMethodUnmarshalAPERLegacy(v *ListeningSubframePattern, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeListeningSubframePatternMethodUnmarshalAPERWithOptions(v *ListeningSubframePattern, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeListeningSubframePatternValueCodecFieldCapture(v *ListeningSubframePatternValueCodec) *func(ListeningSubframePattern, aper.DecodeState) (ListeningSubframePattern, aper.Snapshot) {
	return &v.capture
}
func BridgeListeningSubframePatternValueCodecFieldCompare(v *ListeningSubframePatternValueCodec) *func(ListeningSubframePattern, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeListeningSubframePatternValueCodecFieldContext(v *ListeningSubframePatternValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeListeningSubframePatternValueCodecFieldDecode(v *ListeningSubframePatternValueCodec) *func([]byte, aper.DecodeState) (ListeningSubframePattern, error) {
	return &v.decode
}
func BridgeListeningSubframePatternValueCodecFieldEncode(v *ListeningSubframePatternValueCodec) *func(ListeningSubframePattern, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeListeningSubframePatternValueCodecFieldPath(v *ListeningSubframePatternValueCodec) *aper.Path {
	return &v.path
}
func BridgeListeningSubframePatternValueCodecMethodEncodeBudgetValue(v ListeningSubframePatternValueCodec, a0 ListeningSubframePattern, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeListeningSubframePatternValueCodecMethodEncodeChanged(v ListeningSubframePatternValueCodec, a0 ListeningSubframePattern, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationCauseIEBindingFieldCodec(v *LocationReportingFailureIndicationCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeLocationReportingFailureIndicationCauseIEBindingFieldGet(v *LocationReportingFailureIndicationCauseIEBinding) *func(*LocationReportingFailureIndicationIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeLocationReportingFailureIndicationCauseIEBindingFieldInfo(v *LocationReportingFailureIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportingFailureIndicationCauseIEBindingFieldInject(v *LocationReportingFailureIndicationCauseIEBinding) *func(s14.Cause) LocationReportingFailureIndicationIEValue {
	return &v.inject
}
func BridgeLocationReportingFailureIndicationENBUES1APIDIEBindingFieldCodec(v *LocationReportingFailureIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeLocationReportingFailureIndicationENBUES1APIDIEBindingFieldGet(v *LocationReportingFailureIndicationENBUES1APIDIEBinding) *func(*LocationReportingFailureIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeLocationReportingFailureIndicationENBUES1APIDIEBindingFieldInfo(v *LocationReportingFailureIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeLocationReportingFailureIndicationENBUES1APIDIEBindingFieldInject(v *LocationReportingFailureIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) LocationReportingFailureIndicationIEValue {
	return &v.inject
}
func BridgeLocationReportingFailureIndicationIEContainerAPERValueFieldContext(v *LocationReportingFailureIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEContainerAPERValueFieldReceived(v *LocationReportingFailureIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEContainerAPERValueFieldReplay(v *LocationReportingFailureIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEContainerAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCapture(v *LocationReportingFailureIndicationIEContainerValueCodec) *func(LocationReportingFailureIndicationIEContainer, aper.DecodeState) (LocationReportingFailureIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldCompare(v *LocationReportingFailureIndicationIEContainerValueCodec) *func(LocationReportingFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldContext(v *LocationReportingFailureIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldDecode(v *LocationReportingFailureIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEContainer, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldEncode(v *LocationReportingFailureIndicationIEContainerValueCodec) *func(LocationReportingFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecFieldPath(v *LocationReportingFailureIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecMethodEncodeBudgetValue(v LocationReportingFailureIndicationIEContainerValueCodec, a0 LocationReportingFailureIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationIEContainerValueCodecMethodEncodeChanged(v LocationReportingFailureIndicationIEContainerValueCodec, a0 LocationReportingFailureIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationIEFieldAPERValueFieldContext(v *LocationReportingFailureIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEFieldAPERValueFieldReceived(v *LocationReportingFailureIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEFieldAPERValueFieldReplay(v *LocationReportingFailureIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEFieldAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationIEFieldFieldReceived(v *LocationReportingFailureIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v *LocationReportingFailureIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEFieldFieldStream(v *LocationReportingFailureIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeLocationReportingFailureIndicationIEFieldFieldWithoutReplay(v *LocationReportingFailureIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(v *LocationReportingFailureIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportingFailureIndicationIEFieldMethodUnmarshalAPERFrom(v *LocationReportingFailureIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCapture(v *LocationReportingFailureIndicationIEFieldValueCodec) *func(LocationReportingFailureIndicationIEField, aper.DecodeState) (LocationReportingFailureIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldCompare(v *LocationReportingFailureIndicationIEFieldValueCodec) *func(LocationReportingFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldContext(v *LocationReportingFailureIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldDecode(v *LocationReportingFailureIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEField, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldEncode(v *LocationReportingFailureIndicationIEFieldValueCodec) *func(LocationReportingFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecFieldPath(v *LocationReportingFailureIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecMethodEncodeBudgetValue(v LocationReportingFailureIndicationIEFieldValueCodec, a0 LocationReportingFailureIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationIEFieldValueCodecMethodEncodeChanged(v LocationReportingFailureIndicationIEFieldValueCodec, a0 LocationReportingFailureIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListAPERValueFieldContext(v *LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecFieldPath(v *LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec, a0 LocationReportingFailureIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec, a0 LocationReportingFailureIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationIEValueFieldId(v *LocationReportingFailureIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeLocationReportingFailureIndicationIEValueFieldIsOpaque(v *LocationReportingFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeLocationReportingFailureIndicationIEValueFieldOpaque(v *LocationReportingFailureIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLocationReportingFailureIndicationIEValueFieldReceived(v *LocationReportingFailureIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEValueFieldReplay(v *LocationReportingFailureIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEValueFieldRowCause(v *LocationReportingFailureIndicationIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeLocationReportingFailureIndicationIEValueFieldRowENBUES1APID(v *LocationReportingFailureIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeLocationReportingFailureIndicationIEValueFieldRowMMEUES1APID(v *LocationReportingFailureIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeLocationReportingFailureIndicationIEValueMethodCaptureSemantics(v LocationReportingFailureIndicationIEValue, a0 aper.SemanticCapture) LocationReportingFailureIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeLocationReportingFailureIndicationIEValueMethodCompareSemantics(v LocationReportingFailureIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeLocationReportingFailureIndicationIEValueMethodDecode(v LocationReportingFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (LocationReportingFailureIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeLocationReportingFailureIndicationIEValueMethodEncode(v LocationReportingFailureIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeLocationReportingFailureIndicationIEValueMethodEncodeFresh(v LocationReportingFailureIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeLocationReportingFailureIndicationIEValueMethodMatchesID(v LocationReportingFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLocationReportingFailureIndicationIEValueMethodReason(v LocationReportingFailureIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeLocationReportingFailureIndicationIEValueMethodRule(v LocationReportingFailureIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
