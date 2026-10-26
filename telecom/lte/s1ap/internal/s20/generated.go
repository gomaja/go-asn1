// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s20 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s20

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// CellTrafficTraceIEContainer is ProtocolIE-Container {{CellTrafficTraceIEs}} of TS 36.413: a list of CellTrafficTraceIEField values.
type CellTrafficTraceIEContainer []CellTrafficTraceIEField

// CellTrafficTraceIEField is ProtocolIE-Field {{CellTrafficTraceIEs}} of TS 36.413: an information element field.
type CellTrafficTraceIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         CellTrafficTraceIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEField) WithoutReplay() CellTrafficTraceIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *CellTrafficTraceIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *CellTrafficTraceIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *CellTrafficTraceIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellTrafficTraceIEField{}
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
	var zero CellTrafficTraceIEValue

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

// ERABUsageReportItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABUsageReportItemIEs}} of TS 36.413: a single information element field.
type ERABUsageReportItemIEValueProtocolIESingleContainer = ERABUsageReportItemIEField

// ERABToBeSwitchedULItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABToBeSwitchedULItemIEs}} of TS 36.413: a single information element field.
type ERABToBeSwitchedULItemIEValueProtocolIESingleContainer = ERABToBeSwitchedULItemIEField

// ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABToBeModifiedItemBearerModIndIEs}} of TS 36.413: a single information element field.
type ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer = ERABToBeModifiedItemBearerModIndIEField

// ERABUsageReportItemERABUsageReportItemIEBinding binds ERABUsageReportItem to the E-RABUsageReportItemIEs object set of TS 36.413.
type ERABUsageReportItemERABUsageReportItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABUsageReportItemValueCodec
	inject func(ERABUsageReportItem,

	) ERABUsageReportItemIEValue

	get func(*ERABUsageReportItemIEValue,

	) (*ERABUsageReportItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABUsageReportItemERABUsageReportItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABUsageReportItemERABUsageReportItemIEBinding) Codec() ERABUsageReportItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABUsageReportItemERABUsageReportItemIEBinding) New(value ERABUsageReportItem,

) (ERABUsageReportItemIEField, error) {
	if b.inject == nil {
		return ERABUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABUsageReportItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABUsageReportItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABUsageReportItemERABUsageReportItemIEBinding) Get(field *ERABUsageReportItemIEField) (*ERABUsageReportItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABUsageReportItemValueCodec is the concrete ValueCodec[ERABUsageReportItem].
type ERABUsageReportItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItem,

		error)
	encode func(ERABUsageReportItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItem, aper.DecodeState,

	) (ERABUsageReportItem, aper.Snapshot,

	)
	compare func(ERABUsageReportItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemValueCodec) New(value ERABUsageReportItem,

) (ERABUsageReportItemAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemValueCodec) EncodeAPER(value ERABUsageReportItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemValueCodec) encodeBudgetValue(value ERABUsageReportItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemValueCodec) encodeChanged(value ERABUsageReportItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEField is ProtocolIE-Field {{E-RABUsageReportItemIEs}} of TS 36.413: an information element field.
type ERABUsageReportItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABUsageReportItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEField) WithoutReplay() ERABUsageReportItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABUsageReportItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABUsageReportItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABUsageReportItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABUsageReportItemIEField{}
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
	var zero ERABUsageReportItemIEValue

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

// CellTrafficTraceMMEUES1APIDIEBinding binds MMEUES1APID to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTraceMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b CellTrafficTraceMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTraceMMEUES1APIDIEBinding) Get(field *CellTrafficTraceIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellTrafficTraceENBUES1APIDIEBinding binds ENBUES1APID to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTraceENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b CellTrafficTraceENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTraceENBUES1APIDIEBinding) Get(field *CellTrafficTraceIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellTrafficTraceEUTRANTraceIDIEBinding binds EUTRANTraceID to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTraceEUTRANTraceIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EUTRANTraceIDValueCodec
	inject func(s00.EUTRANTraceID,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*s00.EUTRANTraceID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceEUTRANTraceIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceEUTRANTraceIDIEBinding) Codec() s00.EUTRANTraceIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b CellTrafficTraceEUTRANTraceIDIEBinding) New(value s00.EUTRANTraceID,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEUTRANTraceIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTraceEUTRANTraceIDIEBinding) Get(field *CellTrafficTraceIEField) (*s00.EUTRANTraceID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellTrafficTraceEUTRANCGIIEBinding binds EUTRANCGI to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTraceEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  EUTRANCGIValueCodec
	inject func(EUTRANCGI,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceEUTRANCGIIEBinding) Codec() EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b CellTrafficTraceEUTRANCGIIEBinding) New(value EUTRANCGI,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTraceEUTRANCGIIEBinding) Get(field *CellTrafficTraceIEField) (*EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// EUTRANCGIValueCodec is the concrete ValueCodec[EUTRANCGI].
type EUTRANCGIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EUTRANCGI,

		error)
	encode func(EUTRANCGI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EUTRANCGI, aper.DecodeState,

	) (EUTRANCGI, aper.Snapshot,

	)
	compare func(EUTRANCGI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EUTRANCGIValueCodec) New(value EUTRANCGI,

) (EUTRANCGIAPERValue, error) {
	if c.encode == nil {
		return EUTRANCGIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANCGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANCGIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EUTRANCGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EUTRANCGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANCGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EUTRANCGIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EUTRANCGIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EUTRANCGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EUTRANCGIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EUTRANCGIValueCodec) EncodeAPER(value EUTRANCGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EUTRANCGIValueCodec) encodeBudgetValue(value EUTRANCGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EUTRANCGIValueCodec) encodeChanged(value EUTRANCGI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceTransportLayerAddressIEBinding binds TransportLayerAddress to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTraceTransportLayerAddressIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TransportLayerAddressValueCodec
	inject func(s00.TransportLayerAddress,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*s00.TransportLayerAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTraceTransportLayerAddressIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTraceTransportLayerAddressIEBinding) Codec() s02.TransportLayerAddressValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b CellTrafficTraceTransportLayerAddressIEBinding) New(value s00.TransportLayerAddress,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTraceTransportLayerAddressIEBinding) Get(field *CellTrafficTraceIEField) (*s00.TransportLayerAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellTrafficTracePrivacyIndicatorIEBinding binds PrivacyIndicator to the CellTrafficTraceIEs object set of TS 36.413.
type CellTrafficTracePrivacyIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PrivacyIndicatorValueCodec
	inject func(s00.PrivacyIndicator,

	) CellTrafficTraceIEValue

	get func(*CellTrafficTraceIEValue,

	) (*s00.PrivacyIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b CellTrafficTracePrivacyIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b CellTrafficTracePrivacyIndicatorIEBinding) Codec() s01.PrivacyIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b CellTrafficTracePrivacyIndicatorIEBinding) New(value s00.PrivacyIndicator,

) (CellTrafficTraceIEField, error) {
	if b.inject == nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePrivacyIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return CellTrafficTraceIEField{}, aper.OperationError(err, "Value.New")
	}
	return CellTrafficTraceIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b CellTrafficTracePrivacyIndicatorIEBinding) Get(field *CellTrafficTraceIEField) (*s00.PrivacyIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSubjecttoDataForwardingListValueCodec is the concrete ValueCodec[ERABSubjecttoDataForwardingList].
type ERABSubjecttoDataForwardingListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSubjecttoDataForwardingList,

		error)
	encode func(ERABSubjecttoDataForwardingList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSubjecttoDataForwardingList, aper.DecodeState,

	) (ERABSubjecttoDataForwardingList, aper.Snapshot,

	)
	compare func(ERABSubjecttoDataForwardingList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSubjecttoDataForwardingListValueCodec) New(value ERABSubjecttoDataForwardingList,

) (ERABSubjecttoDataForwardingListAPERValue, error) {
	if c.encode == nil {
		return ERABSubjecttoDataForwardingListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSubjecttoDataForwardingListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSubjecttoDataForwardingListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSubjecttoDataForwardingListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSubjecttoDataForwardingListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSubjecttoDataForwardingListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSubjecttoDataForwardingListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSubjecttoDataForwardingListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSubjecttoDataForwardingListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSubjecttoDataForwardingListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSubjecttoDataForwardingListValueCodec) EncodeAPER(value ERABSubjecttoDataForwardingListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSubjecttoDataForwardingListValueCodec) encodeBudgetValue(value ERABSubjecttoDataForwardingList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSubjecttoDataForwardingListValueCodec) encodeChanged(value ERABSubjecttoDataForwardingList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedListBearerModIndValueCodec is the concrete ValueCodec[ERABToBeModifiedListBearerModInd].
type ERABToBeModifiedListBearerModIndValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedListBearerModInd,

		error)
	encode func(ERABToBeModifiedListBearerModInd,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedListBearerModInd, aper.DecodeState,

	) (ERABToBeModifiedListBearerModInd, aper.Snapshot,

	)
	compare func(ERABToBeModifiedListBearerModInd, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedListBearerModIndValueCodec) New(value ERABToBeModifiedListBearerModInd,

) (ERABToBeModifiedListBearerModIndAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedListBearerModIndAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedListBearerModIndValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedListBearerModIndAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedListBearerModIndAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedListBearerModIndAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedListBearerModIndAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedListBearerModIndAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedListBearerModIndValueCodec) EncodeAPER(value ERABToBeModifiedListBearerModIndAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedListBearerModIndValueCodec) encodeBudgetValue(value ERABToBeModifiedListBearerModInd,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedListBearerModIndValueCodec) encodeChanged(value ERABToBeModifiedListBearerModInd,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupListBearerSUResValueCodec is the concrete ValueCodec[ERABSetupListBearerSURes].
type ERABSetupListBearerSUResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupListBearerSURes,

		error)
	encode func(ERABSetupListBearerSURes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupListBearerSURes, aper.DecodeState,

	) (ERABSetupListBearerSURes, aper.Snapshot,

	)
	compare func(ERABSetupListBearerSURes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupListBearerSUResValueCodec) New(value ERABSetupListBearerSURes,

) (ERABSetupListBearerSUResAPERValue, error) {
	if c.encode == nil {
		return ERABSetupListBearerSUResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupListBearerSUResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupListBearerSUResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupListBearerSUResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupListBearerSUResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupListBearerSUResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupListBearerSUResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupListBearerSUResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupListBearerSUResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupListBearerSUResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupListBearerSUResValueCodec) EncodeAPER(value ERABSetupListBearerSUResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupListBearerSUResValueCodec) encodeBudgetValue(value ERABSetupListBearerSURes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupListBearerSUResValueCodec) encodeChanged(value ERABSetupListBearerSURes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding binds ERABToBeModifiedItemBearerModInd to the E-RABToBeModifiedItemBearerModIndIEs object set of TS 36.413.
type ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeModifiedItemBearerModIndValueCodec
	inject func(ERABToBeModifiedItemBearerModInd,

	) ERABToBeModifiedItemBearerModIndIEValue

	get func(*ERABToBeModifiedItemBearerModIndIEValue,

	) (*ERABToBeModifiedItemBearerModInd,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding) Codec() ERABToBeModifiedItemBearerModIndValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding) New(value ERABToBeModifiedItemBearerModInd,

) (ERABToBeModifiedItemBearerModIndIEField, error) {
	if b.inject == nil {
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding) Get(field *ERABToBeModifiedItemBearerModIndIEField) (*ERABToBeModifiedItemBearerModInd,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeModifiedItemBearerModIndValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModInd].
type ERABToBeModifiedItemBearerModIndValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModInd,

		error)
	encode func(ERABToBeModifiedItemBearerModInd,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModInd, aper.DecodeState,

	) (ERABToBeModifiedItemBearerModInd, aper.Snapshot,

	)
	compare func(ERABToBeModifiedItemBearerModInd, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndValueCodec) New(value ERABToBeModifiedItemBearerModInd,

) (ERABToBeModifiedItemBearerModIndAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModInd,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModInd,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEField is ProtocolIE-Field {{E-RABToBeModifiedItemBearerModIndIEs}} of TS 36.413: an information element field.
type ERABToBeModifiedItemBearerModIndIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeModifiedItemBearerModIndIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEField) WithoutReplay() ERABToBeModifiedItemBearerModIndIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeModifiedItemBearerModIndIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeModifiedItemBearerModIndIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeModifiedItemBearerModIndIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModIndIEField{}
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
	var zero ERABToBeModifiedItemBearerModIndIEValue

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

// ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding binds ERABToBeSwitchedULItem to the E-RABToBeSwitchedULItemIEs object set of TS 36.413.
type ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABToBeSwitchedULItemValueCodec
	inject func(ERABToBeSwitchedULItem,

	) ERABToBeSwitchedULItemIEValue

	get func(*ERABToBeSwitchedULItemIEValue,

	) (*ERABToBeSwitchedULItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding) Codec() ERABToBeSwitchedULItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding) New(value ERABToBeSwitchedULItem,

) (ERABToBeSwitchedULItemIEField, error) {
	if b.inject == nil {
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABToBeSwitchedULItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding) Get(field *ERABToBeSwitchedULItemIEField) (*ERABToBeSwitchedULItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABToBeSwitchedULItemValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItem].
type ERABToBeSwitchedULItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItem,

		error)
	encode func(ERABToBeSwitchedULItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItem, aper.DecodeState,

	) (ERABToBeSwitchedULItem, aper.Snapshot,

	)
	compare func(ERABToBeSwitchedULItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemValueCodec) New(value ERABToBeSwitchedULItem,

) (ERABToBeSwitchedULItemAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemValueCodec) EncodeAPER(value ERABToBeSwitchedULItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemValueCodec) encodeChanged(value ERABToBeSwitchedULItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEField is ProtocolIE-Field {{E-RABToBeSwitchedULItemIEs}} of TS 36.413: an information element field.
type ERABToBeSwitchedULItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABToBeSwitchedULItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEField) WithoutReplay() ERABToBeSwitchedULItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABToBeSwitchedULItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABToBeSwitchedULItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABToBeSwitchedULItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedULItemIEField{}
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
	var zero ERABToBeSwitchedULItemIEValue

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

// ERABSetupListCtxtSUResValueCodec is the concrete ValueCodec[ERABSetupListCtxtSURes].
type ERABSetupListCtxtSUResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupListCtxtSURes,

		error)
	encode func(ERABSetupListCtxtSURes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupListCtxtSURes, aper.DecodeState,

	) (ERABSetupListCtxtSURes, aper.Snapshot,

	)
	compare func(ERABSetupListCtxtSURes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupListCtxtSUResValueCodec) New(value ERABSetupListCtxtSURes,

) (ERABSetupListCtxtSUResAPERValue, error) {
	if c.encode == nil {
		return ERABSetupListCtxtSUResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupListCtxtSUResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupListCtxtSUResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupListCtxtSUResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupListCtxtSUResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupListCtxtSUResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupListCtxtSUResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupListCtxtSUResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupListCtxtSUResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupListCtxtSUResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupListCtxtSUResValueCodec) EncodeAPER(value ERABSetupListCtxtSUResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupListCtxtSUResValueCodec) encodeBudgetValue(value ERABSetupListCtxtSURes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupListCtxtSUResValueCodec) encodeChanged(value ERABSetupListCtxtSURes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ECGIListForRestartValueCodec is the concrete ValueCodec[ECGIListForRestart].
type ECGIListForRestartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ECGIListForRestart,

		error)
	encode func(ECGIListForRestart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ECGIListForRestart, aper.DecodeState,

	) (ECGIListForRestart, aper.Snapshot,

	)
	compare func(ECGIListForRestart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ECGIListForRestartValueCodec) New(value ECGIListForRestart,

) (ECGIListForRestartAPERValue, error) {
	if c.encode == nil {
		return ECGIListForRestartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECGIListForRestartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECGIListForRestartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ECGIListForRestartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ECGIListForRestartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECGIListForRestartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ECGIListForRestartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ECGIListForRestartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ECGIListForRestartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ECGIListForRestartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ECGIListForRestartValueCodec) EncodeAPER(value ECGIListForRestartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECGIListForRestartValueCodec) encodeBudgetValue(value ECGIListForRestart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ECGIListForRestartValueCodec) encodeChanged(value ECGIListForRestart,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULListValueCodec is the concrete ValueCodec[ERABToBeSwitchedULList].
type ERABToBeSwitchedULListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULList,

		error)
	encode func(ERABToBeSwitchedULList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULList, aper.DecodeState,

	) (ERABToBeSwitchedULList, aper.Snapshot,

	)
	compare func(ERABToBeSwitchedULList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULListValueCodec) New(value ERABToBeSwitchedULList,

) (ERABToBeSwitchedULListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULListValueCodec) EncodeAPER(value ERABToBeSwitchedULListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULListValueCodec) encodeBudgetValue(value ERABToBeSwitchedULList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULListValueCodec) encodeChanged(value ERABToBeSwitchedULList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIdentifierAndCELevelForCECapableUEsValueCodec is the concrete ValueCodec[CellIdentifierAndCELevelForCECapableUEs].
type CellIdentifierAndCELevelForCECapableUEsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEs,

		error)
	encode func(CellIdentifierAndCELevelForCECapableUEs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIdentifierAndCELevelForCECapableUEs, aper.DecodeState,

	) (CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot,

	)
	compare func(CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIdentifierAndCELevelForCECapableUEsValueCodec) New(value CellIdentifierAndCELevelForCECapableUEs,

) (CellIdentifierAndCELevelForCECapableUEsAPERValue, error) {
	if c.encode == nil {
		return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIdentifierAndCELevelForCECapableUEsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIdentifierAndCELevelForCECapableUEsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIdentifierAndCELevelForCECapableUEsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIdentifierAndCELevelForCECapableUEsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIdentifierAndCELevelForCECapableUEsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIdentifierAndCELevelForCECapableUEsValueCodec) EncodeAPER(value CellIdentifierAndCELevelForCECapableUEsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIdentifierAndCELevelForCECapableUEsValueCodec) encodeBudgetValue(value CellIdentifierAndCELevelForCECapableUEs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIdentifierAndCELevelForCECapableUEsValueCodec) encodeChanged(value CellIdentifierAndCELevelForCECapableUEs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// AssistanceDataForCECapableUEsValueCodec is the concrete ValueCodec[AssistanceDataForCECapableUEs].
type AssistanceDataForCECapableUEsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (AssistanceDataForCECapableUEs,

		error)
	encode func(AssistanceDataForCECapableUEs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(AssistanceDataForCECapableUEs, aper.DecodeState,

	) (AssistanceDataForCECapableUEs, aper.Snapshot,

	)
	compare func(AssistanceDataForCECapableUEs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c AssistanceDataForCECapableUEsValueCodec) New(value AssistanceDataForCECapableUEs,

) (AssistanceDataForCECapableUEsAPERValue, error) {
	if c.encode == nil {
		return AssistanceDataForCECapableUEsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceDataForCECapableUEsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceDataForCECapableUEsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return AssistanceDataForCECapableUEsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c AssistanceDataForCECapableUEsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceDataForCECapableUEsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return AssistanceDataForCECapableUEsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return AssistanceDataForCECapableUEsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return AssistanceDataForCECapableUEsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return AssistanceDataForCECapableUEsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c AssistanceDataForCECapableUEsValueCodec) EncodeAPER(value AssistanceDataForCECapableUEsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceDataForCECapableUEsValueCodec) encodeBudgetValue(value AssistanceDataForCECapableUEs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c AssistanceDataForCECapableUEsValueCodec) encodeChanged(value AssistanceDataForCECapableUEs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinEAIValueCodec is the concrete ValueCodec[CancelledCellinEAI].
type CancelledCellinEAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinEAI,

		error)
	encode func(CancelledCellinEAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinEAI, aper.DecodeState,

	) (CancelledCellinEAI, aper.Snapshot,

	)
	compare func(CancelledCellinEAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinEAIValueCodec) New(value CancelledCellinEAI,

) (CancelledCellinEAIAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinEAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinEAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinEAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinEAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinEAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinEAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinEAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinEAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinEAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinEAIValueCodec) EncodeAPER(value CancelledCellinEAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CancelledCellinEAIValueCodec) encodeBudgetValue(value CancelledCellinEAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinEAIValueCodec) encodeChanged(value CancelledCellinEAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinEAIItemValueCodec is the concrete ValueCodec[CancelledCellinEAIItem].
type CancelledCellinEAIItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinEAIItem,

		error)
	encode func(CancelledCellinEAIItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinEAIItem, aper.DecodeState,

	) (CancelledCellinEAIItem, aper.Snapshot,

	)
	compare func(CancelledCellinEAIItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinEAIItemValueCodec) New(value CancelledCellinEAIItem,

) (CancelledCellinEAIItemAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinEAIItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinEAIItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinEAIItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinEAIItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinEAIItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinEAIItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinEAIItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinEAIItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinEAIItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinEAIItemValueCodec) EncodeAPER(value CancelledCellinEAIItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CancelledCellinEAIItemValueCodec) encodeBudgetValue(value CancelledCellinEAIItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinEAIItemValueCodec) encodeChanged(value CancelledCellinEAIItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinTAIValueCodec is the concrete ValueCodec[CancelledCellinTAI].
type CancelledCellinTAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinTAI,

		error)
	encode func(CancelledCellinTAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinTAI, aper.DecodeState,

	) (CancelledCellinTAI, aper.Snapshot,

	)
	compare func(CancelledCellinTAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinTAIValueCodec) New(value CancelledCellinTAI,

) (CancelledCellinTAIAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinTAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinTAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinTAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinTAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinTAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinTAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinTAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinTAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinTAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinTAIValueCodec) EncodeAPER(value CancelledCellinTAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CancelledCellinTAIValueCodec) encodeBudgetValue(value CancelledCellinTAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinTAIValueCodec) encodeChanged(value CancelledCellinTAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CancelledCellinTAIItemValueCodec is the concrete ValueCodec[CancelledCellinTAIItem].
type CancelledCellinTAIItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CancelledCellinTAIItem,

		error)
	encode func(CancelledCellinTAIItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CancelledCellinTAIItem, aper.DecodeState,

	) (CancelledCellinTAIItem, aper.Snapshot,

	)
	compare func(CancelledCellinTAIItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CancelledCellinTAIItemValueCodec) New(value CancelledCellinTAIItem,

) (CancelledCellinTAIItemAPERValue, error) {
	if c.encode == nil {
		return CancelledCellinTAIItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CancelledCellinTAIItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CancelledCellinTAIItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CancelledCellinTAIItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CancelledCellinTAIItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CancelledCellinTAIItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CancelledCellinTAIItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CancelledCellinTAIItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CancelledCellinTAIItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CancelledCellinTAIItemValueCodec) EncodeAPER(value CancelledCellinTAIItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CancelledCellinTAIItemValueCodec) encodeBudgetValue(value CancelledCellinTAIItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CancelledCellinTAIItemValueCodec) encodeChanged(value CancelledCellinTAIItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDBroadcastValueCodec is the concrete ValueCodec[CellIDBroadcast].
type CellIDBroadcastValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDBroadcast,

		error)
	encode func(CellIDBroadcast,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDBroadcast, aper.DecodeState,

	) (CellIDBroadcast, aper.Snapshot,

	)
	compare func(CellIDBroadcast, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDBroadcastValueCodec) New(value CellIDBroadcast,

) (CellIDBroadcastAPERValue, error) {
	if c.encode == nil {
		return CellIDBroadcastAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDBroadcastAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDBroadcastAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDBroadcastAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDBroadcastValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDBroadcastAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDBroadcastAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDBroadcastAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDBroadcastAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDBroadcastAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDBroadcastValueCodec) EncodeAPER(value CellIDBroadcastAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIDBroadcastValueCodec) encodeBudgetValue(value CellIDBroadcast,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDBroadcastValueCodec) encodeChanged(value CellIDBroadcast,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDBroadcastItemValueCodec is the concrete ValueCodec[CellIDBroadcastItem].
type CellIDBroadcastItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDBroadcastItem,

		error)
	encode func(CellIDBroadcastItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDBroadcastItem, aper.DecodeState,

	) (CellIDBroadcastItem, aper.Snapshot,

	)
	compare func(CellIDBroadcastItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDBroadcastItemValueCodec) New(value CellIDBroadcastItem,

) (CellIDBroadcastItemAPERValue, error) {
	if c.encode == nil {
		return CellIDBroadcastItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDBroadcastItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDBroadcastItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDBroadcastItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDBroadcastItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDBroadcastItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDBroadcastItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDBroadcastItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDBroadcastItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDBroadcastItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDBroadcastItemValueCodec) EncodeAPER(value CellIDBroadcastItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIDBroadcastItemValueCodec) encodeBudgetValue(value CellIDBroadcastItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDBroadcastItemValueCodec) encodeChanged(value CellIDBroadcastItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDCancelledValueCodec is the concrete ValueCodec[CellIDCancelled].
type CellIDCancelledValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDCancelled,

		error)
	encode func(CellIDCancelled,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDCancelled, aper.DecodeState,

	) (CellIDCancelled, aper.Snapshot,

	)
	compare func(CellIDCancelled, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDCancelledValueCodec) New(value CellIDCancelled,

) (CellIDCancelledAPERValue, error) {
	if c.encode == nil {
		return CellIDCancelledAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDCancelledAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDCancelledAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDCancelledAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDCancelledValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDCancelledAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDCancelledAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDCancelledAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDCancelledAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDCancelledAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDCancelledValueCodec) EncodeAPER(value CellIDCancelledAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIDCancelledValueCodec) encodeBudgetValue(value CellIDCancelled,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDCancelledValueCodec) encodeChanged(value CellIDCancelled,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIDCancelledItemValueCodec is the concrete ValueCodec[CellIDCancelledItem].
type CellIDCancelledItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIDCancelledItem,

		error)
	encode func(CellIDCancelledItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIDCancelledItem, aper.DecodeState,

	) (CellIDCancelledItem, aper.Snapshot,

	)
	compare func(CellIDCancelledItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIDCancelledItemValueCodec) New(value CellIDCancelledItem,

) (CellIDCancelledItemAPERValue, error) {
	if c.encode == nil {
		return CellIDCancelledItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIDCancelledItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIDCancelledItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIDCancelledItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIDCancelledItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIDCancelledItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIDCancelledItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIDCancelledItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIDCancelledItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIDCancelledItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIDCancelledItemValueCodec) EncodeAPER(value CellIDCancelledItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIDCancelledItemValueCodec) encodeBudgetValue(value CellIDCancelledItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIDCancelledItemValueCodec) encodeChanged(value CellIDCancelledItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIdListforMDTValueCodec is the concrete ValueCodec[CellIdListforMDT].
type CellIdListforMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIdListforMDT,

		error)
	encode func(CellIdListforMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIdListforMDT, aper.DecodeState,

	) (CellIdListforMDT, aper.Snapshot,

	)
	compare func(CellIdListforMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIdListforMDTValueCodec) New(value CellIdListforMDT,

) (CellIdListforMDTAPERValue, error) {
	if c.encode == nil {
		return CellIdListforMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIdListforMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIdListforMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIdListforMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIdListforMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIdListforMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIdListforMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIdListforMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIdListforMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIdListforMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIdListforMDTValueCodec) EncodeAPER(value CellIdListforMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIdListforMDTValueCodec) encodeBudgetValue(value CellIdListforMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIdListforMDTValueCodec) encodeChanged(value CellIdListforMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellIdListforQMCValueCodec is the concrete ValueCodec[CellIdListforQMC].
type CellIdListforQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellIdListforQMC,

		error)
	encode func(CellIdListforQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellIdListforQMC, aper.DecodeState,

	) (CellIdListforQMC, aper.Snapshot,

	)
	compare func(CellIdListforQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellIdListforQMCValueCodec) New(value CellIdListforQMC,

) (CellIdListforQMCAPERValue, error) {
	if c.encode == nil {
		return CellIdListforQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellIdListforQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellIdListforQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellIdListforQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellIdListforQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellIdListforQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellIdListforQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellIdListforQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellIdListforQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellIdListforQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellIdListforQMCValueCodec) EncodeAPER(value CellIdListforQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellIdListforQMCValueCodec) encodeBudgetValue(value CellIdListforQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellIdListforQMCValueCodec) encodeChanged(value CellIdListforQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinEAIValueCodec is the concrete ValueCodec[CompletedCellinEAI].
type CompletedCellinEAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinEAI,

		error)
	encode func(CompletedCellinEAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinEAI, aper.DecodeState,

	) (CompletedCellinEAI, aper.Snapshot,

	)
	compare func(CompletedCellinEAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinEAIValueCodec) New(value CompletedCellinEAI,

) (CompletedCellinEAIAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinEAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinEAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinEAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinEAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinEAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinEAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinEAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinEAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinEAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinEAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinEAIValueCodec) EncodeAPER(value CompletedCellinEAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CompletedCellinEAIValueCodec) encodeBudgetValue(value CompletedCellinEAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinEAIValueCodec) encodeChanged(value CompletedCellinEAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinEAIItemValueCodec is the concrete ValueCodec[CompletedCellinEAIItem].
type CompletedCellinEAIItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinEAIItem,

		error)
	encode func(CompletedCellinEAIItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinEAIItem, aper.DecodeState,

	) (CompletedCellinEAIItem, aper.Snapshot,

	)
	compare func(CompletedCellinEAIItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinEAIItemValueCodec) New(value CompletedCellinEAIItem,

) (CompletedCellinEAIItemAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinEAIItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinEAIItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinEAIItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinEAIItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinEAIItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinEAIItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinEAIItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinEAIItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinEAIItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinEAIItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinEAIItemValueCodec) EncodeAPER(value CompletedCellinEAIItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CompletedCellinEAIItemValueCodec) encodeBudgetValue(value CompletedCellinEAIItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinEAIItemValueCodec) encodeChanged(value CompletedCellinEAIItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinTAIValueCodec is the concrete ValueCodec[CompletedCellinTAI].
type CompletedCellinTAIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinTAI,

		error)
	encode func(CompletedCellinTAI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinTAI, aper.DecodeState,

	) (CompletedCellinTAI, aper.Snapshot,

	)
	compare func(CompletedCellinTAI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinTAIValueCodec) New(value CompletedCellinTAI,

) (CompletedCellinTAIAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinTAIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinTAIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinTAIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinTAIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinTAIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinTAIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinTAIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinTAIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinTAIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinTAIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinTAIValueCodec) EncodeAPER(value CompletedCellinTAIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CompletedCellinTAIValueCodec) encodeBudgetValue(value CompletedCellinTAI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinTAIValueCodec) encodeChanged(value CompletedCellinTAI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CompletedCellinTAIItemValueCodec is the concrete ValueCodec[CompletedCellinTAIItem].
type CompletedCellinTAIItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CompletedCellinTAIItem,

		error)
	encode func(CompletedCellinTAIItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CompletedCellinTAIItem, aper.DecodeState,

	) (CompletedCellinTAIItem, aper.Snapshot,

	)
	compare func(CompletedCellinTAIItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CompletedCellinTAIItemValueCodec) New(value CompletedCellinTAIItem,

) (CompletedCellinTAIItemAPERValue, error) {
	if c.encode == nil {
		return CompletedCellinTAIItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CompletedCellinTAIItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CompletedCellinTAIItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CompletedCellinTAIItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CompletedCellinTAIItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CompletedCellinTAIItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CompletedCellinTAIItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CompletedCellinTAIItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CompletedCellinTAIItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CompletedCellinTAIItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CompletedCellinTAIItemValueCodec) EncodeAPER(value CompletedCellinTAIItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CompletedCellinTAIItemValueCodec) encodeBudgetValue(value CompletedCellinTAIItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CompletedCellinTAIItemValueCodec) encodeChanged(value CompletedCellinTAIItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ECGIListValueCodec is the concrete ValueCodec[ECGIList].
type ECGIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ECGIList,

		error)
	encode func(ECGIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ECGIList, aper.DecodeState,

	) (ECGIList, aper.Snapshot,

	)
	compare func(ECGIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ECGIListValueCodec) New(value ECGIList,

) (ECGIListAPERValue, error) {
	if c.encode == nil {
		return ECGIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECGIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECGIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ECGIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ECGIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECGIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ECGIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ECGIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ECGIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ECGIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ECGIListValueCodec) EncodeAPER(value ECGIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECGIListValueCodec) encodeBudgetValue(value ECGIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ECGIListValueCodec) encodeChanged(value ECGIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportListValueCodec is the concrete ValueCodec[ERABUsageReportList].
type ERABUsageReportListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportList,

		error)
	encode func(ERABUsageReportList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportList, aper.DecodeState,

	) (ERABUsageReportList, aper.Snapshot,

	)
	compare func(ERABUsageReportList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportListValueCodec) New(value ERABUsageReportList,

) (ERABUsageReportListAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportListValueCodec) EncodeAPER(value ERABUsageReportListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportListValueCodec) encodeBudgetValue(value ERABUsageReportList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportListValueCodec) encodeChanged(value ERABUsageReportList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEContainer is ProtocolIE-Container {{E-RABToBeModifiedItemBearerModIndIEs}} of TS 36.413: a list of ERABToBeModifiedItemBearerModIndIEField values.
type ERABToBeModifiedItemBearerModIndIEContainer []ERABToBeModifiedItemBearerModIndIEField

// ERABToBeSwitchedULItemIEContainer is ProtocolIE-Container {{E-RABToBeSwitchedULItemIEs}} of TS 36.413: a list of ERABToBeSwitchedULItemIEField values.
type ERABToBeSwitchedULItemIEContainer []ERABToBeSwitchedULItemIEField

// ERABUsageReportItemIEContainer is ProtocolIE-Container {{E-RABUsageReportItemIEs}} of TS 36.413: a list of ERABUsageReportItemIEField values.
type ERABUsageReportItemIEContainer []ERABUsageReportItemIEField

// ERABUsageReportItemAPERValue is the concrete APERValue[ERABUsageReportItem].
type ERABUsageReportItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABUsageReportItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemAPERValue) WithoutReplay() ERABUsageReportItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANCGIAPERValue is the concrete APERValue[EUTRANCGI].
type EUTRANCGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   EUTRANCGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EUTRANCGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EUTRANCGIAPERValue) WithoutReplay() EUTRANCGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSubjecttoDataForwardingListAPERValue is the concrete APERValue[ERABSubjecttoDataForwardingList].
type ERABSubjecttoDataForwardingListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSubjecttoDataForwardingList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSubjecttoDataForwardingListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSubjecttoDataForwardingListAPERValue) WithoutReplay() ERABSubjecttoDataForwardingListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedListBearerModIndAPERValue is the concrete APERValue[ERABToBeModifiedListBearerModInd].
type ERABToBeModifiedListBearerModIndAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeModifiedListBearerModInd

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedListBearerModIndAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedListBearerModIndAPERValue) WithoutReplay() ERABToBeModifiedListBearerModIndAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupListBearerSUResAPERValue is the concrete APERValue[ERABSetupListBearerSURes].
type ERABSetupListBearerSUResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupListBearerSURes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupListBearerSUResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupListBearerSUResAPERValue) WithoutReplay() ERABSetupListBearerSUResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModInd].
type ERABToBeModifiedItemBearerModIndAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeModifiedItemBearerModInd

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemAPERValue is the concrete APERValue[ERABToBeSwitchedULItem].
type ERABToBeSwitchedULItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSwitchedULItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemAPERValue) WithoutReplay() ERABToBeSwitchedULItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupListCtxtSUResAPERValue is the concrete APERValue[ERABSetupListCtxtSURes].
type ERABSetupListCtxtSUResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupListCtxtSURes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupListCtxtSUResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupListCtxtSUResAPERValue) WithoutReplay() ERABSetupListCtxtSUResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECGIListForRestartAPERValue is the concrete APERValue[ECGIListForRestart].
type ECGIListForRestartAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECGIListForRestart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ECGIListForRestartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ECGIListForRestartAPERValue) WithoutReplay() ECGIListForRestartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULListAPERValue is the concrete APERValue[ERABToBeSwitchedULList].
type ERABToBeSwitchedULListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABToBeSwitchedULList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULListAPERValue) WithoutReplay() ERABToBeSwitchedULListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIdentifierAndCELevelForCECapableUEsAPERValue is the concrete APERValue[CellIdentifierAndCELevelForCECapableUEs].
type CellIdentifierAndCELevelForCECapableUEsAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIdentifierAndCELevelForCECapableUEs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIdentifierAndCELevelForCECapableUEsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdentifierAndCELevelForCECapableUEsAPERValue) WithoutReplay() CellIdentifierAndCELevelForCECapableUEsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceDataForCECapableUEsAPERValue is the concrete APERValue[AssistanceDataForCECapableUEs].
type AssistanceDataForCECapableUEsAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceDataForCECapableUEs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v AssistanceDataForCECapableUEsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v AssistanceDataForCECapableUEsAPERValue) WithoutReplay() AssistanceDataForCECapableUEsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinEAIAPERValue is the concrete APERValue[CancelledCellinEAI].
type CancelledCellinEAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CancelledCellinEAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinEAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIAPERValue) WithoutReplay() CancelledCellinEAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinEAIItemAPERValue is the concrete APERValue[CancelledCellinEAIItem].
type CancelledCellinEAIItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CancelledCellinEAIItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinEAIItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinEAIItemAPERValue) WithoutReplay() CancelledCellinEAIItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinTAIAPERValue is the concrete APERValue[CancelledCellinTAI].
type CancelledCellinTAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CancelledCellinTAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinTAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIAPERValue) WithoutReplay() CancelledCellinTAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CancelledCellinTAIItemAPERValue is the concrete APERValue[CancelledCellinTAIItem].
type CancelledCellinTAIItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CancelledCellinTAIItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CancelledCellinTAIItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CancelledCellinTAIItemAPERValue) WithoutReplay() CancelledCellinTAIItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDBroadcastAPERValue is the concrete APERValue[CellIDBroadcast].
type CellIDBroadcastAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIDBroadcast

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDBroadcastAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastAPERValue) WithoutReplay() CellIDBroadcastAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDBroadcastItemAPERValue is the concrete APERValue[CellIDBroadcastItem].
type CellIDBroadcastItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIDBroadcastItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDBroadcastItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDBroadcastItemAPERValue) WithoutReplay() CellIDBroadcastItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDCancelledAPERValue is the concrete APERValue[CellIDCancelled].
type CellIDCancelledAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIDCancelled

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDCancelledAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledAPERValue) WithoutReplay() CellIDCancelledAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIDCancelledItemAPERValue is the concrete APERValue[CellIDCancelledItem].
type CellIDCancelledItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIDCancelledItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIDCancelledItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIDCancelledItemAPERValue) WithoutReplay() CellIDCancelledItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIdListforMDTAPERValue is the concrete APERValue[CellIdListforMDT].
type CellIdListforMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIdListforMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIdListforMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdListforMDTAPERValue) WithoutReplay() CellIdListforMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellIdListforQMCAPERValue is the concrete APERValue[CellIdListforQMC].
type CellIdListforQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellIdListforQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellIdListforQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellIdListforQMCAPERValue) WithoutReplay() CellIdListforQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinEAIAPERValue is the concrete APERValue[CompletedCellinEAI].
type CompletedCellinEAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CompletedCellinEAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinEAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIAPERValue) WithoutReplay() CompletedCellinEAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinEAIItemAPERValue is the concrete APERValue[CompletedCellinEAIItem].
type CompletedCellinEAIItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CompletedCellinEAIItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinEAIItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinEAIItemAPERValue) WithoutReplay() CompletedCellinEAIItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinTAIAPERValue is the concrete APERValue[CompletedCellinTAI].
type CompletedCellinTAIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CompletedCellinTAI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinTAIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIAPERValue) WithoutReplay() CompletedCellinTAIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CompletedCellinTAIItemAPERValue is the concrete APERValue[CompletedCellinTAIItem].
type CompletedCellinTAIItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CompletedCellinTAIItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CompletedCellinTAIItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CompletedCellinTAIItemAPERValue) WithoutReplay() CompletedCellinTAIItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECGIListAPERValue is the concrete APERValue[ECGIList].
type ECGIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECGIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ECGIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ECGIListAPERValue) WithoutReplay() ECGIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportListAPERValue is the concrete APERValue[ERABUsageReportList].
type ERABUsageReportListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABUsageReportList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportListAPERValue) WithoutReplay() ERABUsageReportListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEValueERABIEContainerListValueCodec is the concrete ValueCodec[CellTrafficTraceIEValueERABIEContainerList].
type CellTrafficTraceIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTraceIEValueERABIEContainerList, error)
	encode  func(CellTrafficTraceIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTraceIEValueERABIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot)
	compare func(CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceIEValueERABIEContainerListValueCodec) New(value CellTrafficTraceIEValueERABIEContainerList) (CellTrafficTraceIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceIEValueERABIEContainerListValueCodec) EncodeAPER(value CellTrafficTraceIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTrafficTraceIEValueERABIEContainerListValueCodec) encodeBudgetValue(value CellTrafficTraceIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceIEValueERABIEContainerListValueCodec) encodeChanged(value CellTrafficTraceIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceIEValueERABIEContainerList is E-RAB-IE-ContainerList {{CellTrafficTraceIEs}} of TS 36.413: a list of information element fields.
type CellTrafficTraceIEValueERABIEContainerList []CellTrafficTraceIEValueProtocolIESingleContainer

// ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} of TS 36.413: a list of information element fields.
type ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList []ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemIEValueERABIEContainerList].
type ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueERABIEContainerList, error)
	encode  func(ERABToBeSwitchedULItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) New(value ERABToBeSwitchedULItemIEValueERABIEContainerList) (ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedULItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} of TS 36.413: a list of information element fields.
type ERABToBeSwitchedULItemIEValueERABIEContainerList []ERABToBeSwitchedULItemIEValueProtocolIESingleContainer

// ERABUsageReportItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABUsageReportItemIEValueERABIEContainerList].
type ERABUsageReportItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueERABIEContainerList, error)
	encode  func(ERABUsageReportItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemIEValueERABIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemIEValueERABIEContainerListValueCodec) New(value ERABUsageReportItemIEValueERABIEContainerList) (ERABUsageReportItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABUsageReportItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABUsageReportItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABUsageReportItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABUsageReportItemIEs}} of TS 36.413: a list of information element fields.
type ERABUsageReportItemIEValueERABIEContainerList []ERABUsageReportItemIEValueProtocolIESingleContainer

// CellTrafficTraceIEFieldValueCodec is the concrete ValueCodec[CellTrafficTraceIEField].
type CellTrafficTraceIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTraceIEField, error)
	encode  func(CellTrafficTraceIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTraceIEField, aper.DecodeState) (CellTrafficTraceIEField, aper.Snapshot)
	compare func(CellTrafficTraceIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceIEFieldValueCodec) New(value CellTrafficTraceIEField) (CellTrafficTraceIEFieldAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceIEFieldValueCodec) EncodeAPER(value CellTrafficTraceIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTrafficTraceIEFieldValueCodec) encodeBudgetValue(value CellTrafficTraceIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceIEFieldValueCodec) encodeChanged(value CellTrafficTraceIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEFieldValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndIEField].
type ERABToBeModifiedItemBearerModIndIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEField, error)
	encode  func(ERABToBeModifiedItemBearerModIndIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndIEField, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndIEFieldValueCodec) New(value ERABToBeModifiedItemBearerModIndIEField) (ERABToBeModifiedItemBearerModIndIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndIEFieldValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndIEFieldValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndIEFieldValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEFieldValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemIEField].
type ERABToBeSwitchedULItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEField, error)
	encode  func(ERABToBeSwitchedULItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemIEField, aper.DecodeState) (ERABToBeSwitchedULItemIEField, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemIEFieldValueCodec) New(value ERABToBeSwitchedULItemIEField) (ERABToBeSwitchedULItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemIEFieldValueCodec) EncodeAPER(value ERABToBeSwitchedULItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemIEFieldValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemIEFieldValueCodec) encodeChanged(value ERABToBeSwitchedULItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEFieldValueCodec is the concrete ValueCodec[ERABUsageReportItemIEField].
type ERABUsageReportItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemIEField, error)
	encode  func(ERABUsageReportItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemIEField, aper.DecodeState) (ERABUsageReportItemIEField, aper.Snapshot)
	compare func(ERABUsageReportItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemIEFieldValueCodec) New(value ERABUsageReportItemIEField) (ERABUsageReportItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemIEFieldValueCodec) EncodeAPER(value ERABUsageReportItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemIEFieldValueCodec) encodeBudgetValue(value ERABUsageReportItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemIEFieldValueCodec) encodeChanged(value ERABUsageReportItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceIEContainerValueCodec is the concrete ValueCodec[CellTrafficTraceIEContainer].
type CellTrafficTraceIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTraceIEContainer, error)
	encode  func(CellTrafficTraceIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTraceIEContainer, aper.DecodeState) (CellTrafficTraceIEContainer, aper.Snapshot)
	compare func(CellTrafficTraceIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceIEContainerValueCodec) New(value CellTrafficTraceIEContainer) (CellTrafficTraceIEContainerAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceIEContainerValueCodec) EncodeAPER(value CellTrafficTraceIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTrafficTraceIEContainerValueCodec) encodeBudgetValue(value CellTrafficTraceIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceIEContainerValueCodec) encodeChanged(value CellTrafficTraceIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEContainerValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndIEContainer].
type ERABToBeModifiedItemBearerModIndIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEContainer, error)
	encode  func(ERABToBeModifiedItemBearerModIndIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndIEContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndIEContainerValueCodec) New(value ERABToBeModifiedItemBearerModIndIEContainer) (ERABToBeModifiedItemBearerModIndIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndIEContainerValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndIEContainerValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndIEContainerValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEContainerValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemIEContainer].
type ERABToBeSwitchedULItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEContainer, error)
	encode  func(ERABToBeSwitchedULItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemIEContainer, aper.DecodeState) (ERABToBeSwitchedULItemIEContainer, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemIEContainerValueCodec) New(value ERABToBeSwitchedULItemIEContainer) (ERABToBeSwitchedULItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemIEContainerValueCodec) EncodeAPER(value ERABToBeSwitchedULItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemIEContainerValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemIEContainerValueCodec) encodeChanged(value ERABToBeSwitchedULItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEContainerValueCodec is the concrete ValueCodec[ERABUsageReportItemIEContainer].
type ERABUsageReportItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemIEContainer, error)
	encode  func(ERABUsageReportItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemIEContainer, aper.DecodeState) (ERABUsageReportItemIEContainer, aper.Snapshot)
	compare func(ERABUsageReportItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemIEContainerValueCodec) New(value ERABUsageReportItemIEContainer) (ERABUsageReportItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemIEContainerValueCodec) EncodeAPER(value ERABUsageReportItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemIEContainerValueCodec) encodeBudgetValue(value ERABUsageReportItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemIEContainerValueCodec) encodeChanged(value ERABUsageReportItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[CellTrafficTraceIEValueProtocolErrorIEContainerList].
type CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTraceIEValueProtocolErrorIEContainerList, error)
	encode  func(CellTrafficTraceIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) New(value CellTrafficTraceIEValueProtocolErrorIEContainerList) (CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value CellTrafficTraceIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value CellTrafficTraceIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{CellTrafficTraceIEs}} of TS 36.413: a list of information element fields.
type CellTrafficTraceIEValueProtocolErrorIEContainerList []CellTrafficTraceIEValueProtocolIESingleContainer

// ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABToBeModifiedItemBearerModIndIEs}} of TS 36.413: a list of information element fields.
type ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList []ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList].
type ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABToBeSwitchedULItemIEs}} of TS 36.413: a list of information element fields.
type ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList []ERABToBeSwitchedULItemIEValueProtocolIESingleContainer

// ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABUsageReportItemIEValueProtocolErrorIEContainerList].
type ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABUsageReportItemIEValueProtocolErrorIEContainerList) (ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABUsageReportItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABUsageReportItemIEs}} of TS 36.413: a list of information element fields.
type ERABUsageReportItemIEValueProtocolErrorIEContainerList []ERABUsageReportItemIEValueProtocolIESingleContainer

// CellTrafficTraceIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[CellTrafficTraceIEValueProtocolIEContainerList].
type CellTrafficTraceIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTraceIEValueProtocolIEContainerList, error)
	encode  func(CellTrafficTraceIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTraceIEValueProtocolIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceIEValueProtocolIEContainerListValueCodec) New(value CellTrafficTraceIEValueProtocolIEContainerList) (CellTrafficTraceIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceIEValueProtocolIEContainerListValueCodec) EncodeAPER(value CellTrafficTraceIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTrafficTraceIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value CellTrafficTraceIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceIEValueProtocolIEContainerListValueCodec) encodeChanged(value CellTrafficTraceIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {CellTrafficTraceIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type CellTrafficTraceIEValueProtocolIEContainerList []CellTrafficTraceIEValueProtocolIESingleContainer

// ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) New(value ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeModifiedItemBearerModIndIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList []ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABToBeSwitchedULItemIEValueProtocolIEContainerList].
type ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolIEContainerList, error)
	encode  func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) New(value ERABToBeSwitchedULItemIEValueProtocolIEContainerList) (ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABToBeSwitchedULItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABToBeSwitchedULItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABToBeSwitchedULItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABToBeSwitchedULItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABToBeSwitchedULItemIEValueProtocolIEContainerList []ERABToBeSwitchedULItemIEValueProtocolIESingleContainer

// ERABUsageReportItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABUsageReportItemIEValueProtocolIEContainerList].
type ERABUsageReportItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueProtocolIEContainerList, error)
	encode  func(ERABUsageReportItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABUsageReportItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) New(value ERABUsageReportItemIEValueProtocolIEContainerList) (ERABUsageReportItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABUsageReportItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABUsageReportItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABUsageReportItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABUsageReportItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABUsageReportItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABUsageReportItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABUsageReportItemIEValueProtocolIEContainerList []ERABUsageReportItemIEValueProtocolIESingleContainer

// CellTrafficTraceIEValueERABIEContainerListAPERValue is the concrete APERValue[CellTrafficTraceIEValueERABIEContainerList].
type CellTrafficTraceIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTrafficTraceIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEValueERABIEContainerListAPERValue) WithoutReplay() CellTrafficTraceIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{CellTrafficTraceIEs}} of TS 36.413: a single information element field.
type CellTrafficTraceIEValueProtocolIESingleContainer = CellTrafficTraceIEField

// ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABToBeSwitchedULItemIEValueERABIEContainerList].
type ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedULItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABUsageReportItemIEValueERABIEContainerList].
type ERABUsageReportItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABUsageReportItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEFieldAPERValue is the concrete APERValue[CellTrafficTraceIEField].
type CellTrafficTraceIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTrafficTraceIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEFieldAPERValue) WithoutReplay() CellTrafficTraceIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndIEFieldAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndIEField].
type ERABToBeModifiedItemBearerModIndIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEFieldAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemIEFieldAPERValue is the concrete APERValue[ERABToBeSwitchedULItemIEField].
type ERABToBeSwitchedULItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEFieldAPERValue) WithoutReplay() ERABToBeSwitchedULItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemIEFieldAPERValue is the concrete APERValue[ERABUsageReportItemIEField].
type ERABUsageReportItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEFieldAPERValue) WithoutReplay() ERABUsageReportItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEContainerAPERValue is the concrete APERValue[CellTrafficTraceIEContainer].
type CellTrafficTraceIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTrafficTraceIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEContainerAPERValue) WithoutReplay() CellTrafficTraceIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndIEContainerAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndIEContainer].
type ERABToBeModifiedItemBearerModIndIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEContainerAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemIEContainerAPERValue is the concrete APERValue[ERABToBeSwitchedULItemIEContainer].
type ERABToBeSwitchedULItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEContainerAPERValue) WithoutReplay() ERABToBeSwitchedULItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemIEContainerAPERValue is the concrete APERValue[ERABUsageReportItemIEContainer].
type ERABUsageReportItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEContainerAPERValue) WithoutReplay() ERABUsageReportItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[CellTrafficTraceIEValueProtocolErrorIEContainerList].
type CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTrafficTraceIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() CellTrafficTraceIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList].
type ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABUsageReportItemIEValueProtocolErrorIEContainerList].
type ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABUsageReportItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceIEValueProtocolIEContainerListAPERValue is the concrete APERValue[CellTrafficTraceIEValueProtocolIEContainerList].
type CellTrafficTraceIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         CellTrafficTraceIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceIEValueProtocolIEContainerListAPERValue) WithoutReplay() CellTrafficTraceIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList].
type ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABToBeSwitchedULItemIEValueProtocolIEContainerList].
type ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABToBeSwitchedULItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABToBeSwitchedULItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABUsageReportItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABUsageReportItemIEValueProtocolIEContainerList].
type ERABUsageReportItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABUsageReportItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABUsageReportItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABUsageReportItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABUsageReportItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APAssistanceDataForCECapableUEs(v *AssistanceDataForCECapableUEs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(&v.CellIdentifierAndCELevelForCECapableUEs, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeInformationForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APAssistanceDataForCECapableUEs(v *AssistanceDataForCECapableUEs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(&v.CellIdentifierAndCELevelForCECapableUEs, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeInformationForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinEAIItem(v *CancelledCellinEAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s00.BridgeCaptureS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCancelledCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinEAIItem(v *CancelledCellinEAIItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s02.BridgeCompareS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCancelledCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinTAIItem(v *CancelledCellinTAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s00.BridgeCaptureS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCancelledCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinTAIItem(v *CancelledCellinTAIItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s02.BridgeCompareS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCancelledCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDBroadcastItem(v *CellIDBroadcastItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIDBroadcastItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDBroadcastItem(v *CellIDBroadcastItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIDBroadcastItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDCancelledItem(v *CellIDCancelledItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s00.BridgeCaptureS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDCancelledItem(v *CellIDCancelledItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s02.BridgeCompareS1APNumberOfBroadcasts(&v.NumberOfBroadcasts, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(v *CellIdentifierAndCELevelForCECapableUEs, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.GlobalCellID, s)
	s00.BridgeCaptureS1APCELevel(&v.CELevel, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(v *CellIdentifierAndCELevelForCECapableUEs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.GlobalCellID, s)
	s02.BridgeCompareS1APCELevel(&v.CELevel, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellTrafficTraceIEValue(v *CellTrafficTraceIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(86):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANTraceID == nil)
				if v.rowEUTRANTraceID != nil {
					s00.BridgeCaptureS1APEUTRANTraceID(v.rowEUTRANTraceID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(131):
			{
				f := s.Begin()
				s.Bool(v.rowTraceCollectionEntityIPAddress == nil)
				if v.rowTraceCollectionEntityIPAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowTraceCollectionEntityIPAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(166):
			{
				f := s.Begin()
				s.Bool(v.rowPrivacyIndicator == nil)
				if v.rowPrivacyIndicator != nil {
					s00.BridgeCaptureS1APPrivacyIndicator(v.rowPrivacyIndicator, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CellTrafficTraceIEValue) captureSemantics(s aper.SemanticCapture) CellTrafficTraceIEValue {
	BridgeCaptureS1APCellTrafficTraceIEValue(&v, &s)
	return v
}
func BridgeCompareS1APCellTrafficTraceIEValue(v *CellTrafficTraceIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(86):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANTraceID == nil)
				if v.rowEUTRANTraceID != nil {
					s02.BridgeCompareS1APEUTRANTraceID(v.rowEUTRANTraceID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(131):
			{
				f := s.Begin()
				s.Bool(v.rowTraceCollectionEntityIPAddress == nil)
				if v.rowTraceCollectionEntityIPAddress != nil {
					s08.BridgeCompareS1APTransportLayerAddress(v.rowTraceCollectionEntityIPAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(166):
			{
				f := s.Begin()
				s.Bool(v.rowPrivacyIndicator == nil)
				if v.rowPrivacyIndicator != nil {
					s02.BridgeCompareS1APPrivacyIndicator(v.rowPrivacyIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CellTrafficTraceIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCellTrafficTraceIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APCompletedCellinEAIItem(v *CompletedCellinEAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCompletedCellinEAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCompletedCellinEAIItem(v *CompletedCellinEAIItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCompletedCellinEAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCompletedCellinTAIItem(v *CompletedCellinTAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCompletedCellinTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCompletedCellinTAIItem(v *CompletedCellinTAIItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEUTRANCGI(&v.ECGI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCompletedCellinTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeModifiedItemBearerModInd(v *ERABToBeModifiedItemBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.DLGTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeModifiedItemBearerModInd(v *ERABToBeModifiedItemBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s08.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.DLGTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeModifiedItemBearerModIndIEValue(v *ERABToBeModifiedItemBearerModIndIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(200):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedItemBearerModInd == nil)
				if v.rowERABToBeModifiedItemBearerModInd != nil {
					BridgeCaptureS1APERABToBeModifiedItemBearerModInd(v.rowERABToBeModifiedItemBearerModInd, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifiedItemBearerModIndIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeModifiedItemBearerModIndIEValue {
	BridgeCaptureS1APERABToBeModifiedItemBearerModIndIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeModifiedItemBearerModIndIEValue(v *ERABToBeModifiedItemBearerModIndIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(200):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedItemBearerModInd == nil)
				if v.rowERABToBeModifiedItemBearerModInd != nil {
					BridgeCompareS1APERABToBeModifiedItemBearerModInd(v.rowERABToBeModifiedItemBearerModInd, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeModifiedItemBearerModIndIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeModifiedItemBearerModIndIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABToBeSwitchedULItem(v *ERABToBeSwitchedULItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeSwitchedULItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABToBeSwitchedULItem(v *ERABToBeSwitchedULItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s08.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABToBeSwitchedULItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABToBeSwitchedULItemIEValue(v *ERABToBeSwitchedULItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(94):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULItem == nil)
				if v.rowERABToBeSwitchedULItem != nil {
					BridgeCaptureS1APERABToBeSwitchedULItem(v.rowERABToBeSwitchedULItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedULItemIEValue) captureSemantics(s aper.SemanticCapture) ERABToBeSwitchedULItemIEValue {
	BridgeCaptureS1APERABToBeSwitchedULItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABToBeSwitchedULItemIEValue(v *ERABToBeSwitchedULItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(94):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULItem == nil)
				if v.rowERABToBeSwitchedULItem != nil {
					BridgeCompareS1APERABToBeSwitchedULItem(v.rowERABToBeSwitchedULItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABToBeSwitchedULItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABToBeSwitchedULItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABUsageReportItem(v *ERABUsageReportItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.StartTimestamp)
	s.Bytes(v.EndTimestamp)
	s.Uint(uint64(v.UsageCountUL))
	s.Uint(uint64(v.UsageCountDL))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABUsageReportItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABUsageReportItem(v *ERABUsageReportItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.StartTimestamp)
	s.Bytes(v.EndTimestamp)
	s.Uint(uint64(v.UsageCountUL))
	s.Uint(uint64(v.UsageCountDL))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeERABUsageReportItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABUsageReportItemIEValue(v *ERABUsageReportItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(267):
			{
				f := s.Begin()
				s.Bool(v.rowERABUsageReportItem == nil)
				if v.rowERABUsageReportItem != nil {
					BridgeCaptureS1APERABUsageReportItem(v.rowERABUsageReportItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABUsageReportItemIEValue) captureSemantics(s aper.SemanticCapture) ERABUsageReportItemIEValue {
	BridgeCaptureS1APERABUsageReportItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABUsageReportItemIEValue(v *ERABUsageReportItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(267):
			{
				f := s.Begin()
				s.Bool(v.rowERABUsageReportItem == nil)
				if v.rowERABUsageReportItem != nil {
					BridgeCompareS1APERABUsageReportItem(v.rowERABUsageReportItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABUsageReportItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABUsageReportItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APEUTRANCGI(v *EUTRANCGI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s00.BridgeCaptureS1APCellIdentity(&v.CellID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEUTRANCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEUTRANCGI(v *EUTRANCGI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APCellIdentity(&v.CellID, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEUTRANCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// AssistanceDataForCECapableUEs represents the ASN.1 type AssistanceDataForCECapableUEs (SEQUENCE).
type AssistanceDataForCECapableUEs struct {
	replay                                  aper.Snapshot
	stream                                  aper.WireSpan
	received                                bool
	withoutReplay                           bool
	receivedAbsolute                        bool
	receivedBytes                           aper.WireSpan
	receivedLocation                        aper.Location
	CellIdentifierAndCELevelForCECapableUEs CellIdentifierAndCELevelForCECapableUEs          `asn1:"tag:0,context,implicit"`
	IEExtensions                            s11.InformationForCECapableUEsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                       bool                                             `asn1:"-" json:"-"`
	extCount                                int64                                            `asn1:"-" json:"-"`
	extPresent                              []bool                                           `asn1:"-" json:"-"`
	extData                                 [][]byte                                         `asn1:"-" json:"-"`
	perPadding                              aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding                           []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin                               []aper.OpaqueOrigin
	extWire                                 []aper.WireSpan
}
type CancelledCellinEAI = []CancelledCellinEAIItem

// CancelledCellinEAIItem represents the ASN.1 type CancelledCellinEAI-Item (SEQUENCE).
type CancelledCellinEAIItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	ECGI               EUTRANCGI                                    `asn1:"tag:0,context,implicit"`
	NumberOfBroadcasts s00.NumberOfBroadcasts                       `asn1:"tag:1,context,implicit"`
	IEExtensions       s08.CancelledCellinEAIItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                         `asn1:"-" json:"-"`
	extCount           int64                                        `asn1:"-" json:"-"`
	extPresent         []bool                                       `asn1:"-" json:"-"`
	extData            [][]byte                                     `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type CancelledCellinTAI = []CancelledCellinTAIItem

// CancelledCellinTAIItem represents the ASN.1 type CancelledCellinTAI-Item (SEQUENCE).
type CancelledCellinTAIItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	ECGI               EUTRANCGI                                    `asn1:"tag:0,context,implicit"`
	NumberOfBroadcasts s00.NumberOfBroadcasts                       `asn1:"tag:1,context,implicit"`
	IEExtensions       s08.CancelledCellinTAIItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                         `asn1:"-" json:"-"`
	extCount           int64                                        `asn1:"-" json:"-"`
	extPresent         []bool                                       `asn1:"-" json:"-"`
	extData            [][]byte                                     `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}

// CellIdentifierAndCELevelForCECapableUEs represents the ASN.1 type CellIdentifierAndCELevelForCECapableUEs (SEQUENCE).
type CellIdentifierAndCELevelForCECapableUEs struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalCellID      EUTRANCGI                                                     `asn1:"tag:0,context,implicit"`
	CELevel           s00.CELevel                                                   `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                          `asn1:"-" json:"-"`
	extCount          int64                                                         `asn1:"-" json:"-"`
	extPresent        []bool                                                        `asn1:"-" json:"-"`
	extData           [][]byte                                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CellIDBroadcast = []CellIDBroadcastItem

// CellIDBroadcastItem represents the ASN.1 type CellID-Broadcast-Item (SEQUENCE).
type CellIDBroadcastItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ECGI              EUTRANCGI                                 `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.CellIDBroadcastItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                      `asn1:"-" json:"-"`
	extCount          int64                                     `asn1:"-" json:"-"`
	extPresent        []bool                                    `asn1:"-" json:"-"`
	extData           [][]byte                                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CellIDCancelled = []CellIDCancelledItem

// CellIDCancelledItem represents the ASN.1 type CellID-Cancelled-Item (SEQUENCE).
type CellIDCancelledItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	ECGI               EUTRANCGI                                 `asn1:"tag:0,context,implicit"`
	NumberOfBroadcasts s00.NumberOfBroadcasts                    `asn1:"tag:1,context,implicit"`
	IEExtensions       s09.CellIDCancelledItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef  bool                                      `asn1:"-" json:"-"`
	extCount           int64                                     `asn1:"-" json:"-"`
	extPresent         []bool                                    `asn1:"-" json:"-"`
	extData            [][]byte                                  `asn1:"-" json:"-"`
	perPadding         aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding      []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin          []aper.OpaqueOrigin
	extWire            []aper.WireSpan
}
type CellIdListforMDT = []EUTRANCGI
type CellIdListforQMC = []EUTRANCGI
type ECGIList = []EUTRANCGI
type CompletedCellinEAI = []CompletedCellinEAIItem

// CompletedCellinEAIItem represents the ASN.1 type CompletedCellinEAI-Item (SEQUENCE).
type CompletedCellinEAIItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ECGI              EUTRANCGI                                    `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.CompletedCellinEAIItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ERABUsageReportList = []ERABUsageReportItemIEValueProtocolIESingleContainer

// ERABUsageReportItem represents the ASN.1 type E-RABUsageReportItem (SEQUENCE).
type ERABUsageReportItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	StartTimestamp    []byte                                    `asn1:"tag:0,context,implicit"`
	EndTimestamp      []byte                                    `asn1:"tag:1,context,implicit"`
	UsageCountUL      uint64                                    `asn1:"tag:2,context,implicit"`
	UsageCountDL      uint64                                    `asn1:"tag:3,context,implicit"`
	IEExtensions      s10.ERABUsageReportItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                      `asn1:"-" json:"-"`
	extCount          int64                                     `asn1:"-" json:"-"`
	extPresent        []bool                                    `asn1:"-" json:"-"`
	extData           [][]byte                                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// EUTRANCGI represents the ASN.1 type EUTRAN-CGI (SEQUENCE).
type EUTRANCGI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNidentity      s00.PLMNidentity                `asn1:"tag:0,context,implicit"`
	CellID            s00.CellIdentity                `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.EUTRANCGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                            `asn1:"-" json:"-"`
	extCount          int64                           `asn1:"-" json:"-"`
	extPresent        []bool                          `asn1:"-" json:"-"`
	extData           [][]byte                        `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ECGIListForRestart = []EUTRANCGI
type CompletedCellinTAI = []CompletedCellinTAIItem

// CompletedCellinTAIItem represents the ASN.1 type CompletedCellinTAI-Item (SEQUENCE).
type CompletedCellinTAIItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ECGI              EUTRANCGI                                    `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.CompletedCellinTAIItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes AssistanceDataForCECapableUEs to APER format.
func (v *AssistanceDataForCECapableUEs) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceDataForCECapableUEs) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.CellIdentifierAndCELevelForCECapableUEs.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cellIdentifierAndCELevelForCECapableUEs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceDataForCECapableUEs from APER format.
func (v *AssistanceDataForCECapableUEs) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AssistanceDataForCECapableUEs) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForCECapableUEs")
	}
	bb.EnterComponent("AssistanceDataForCECapableUEs")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForCECapableUEs")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceDataForCECapableUEs")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataForCECapableUEs")
	}
	v.perPadding = padding
	return nil
}
func (v *AssistanceDataForCECapableUEs) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceDataForCECapableUEs{}
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
	toleranceMark_cellidentifierandcelevelforcecapableues := bb.EnterComponent("CellIdentifierAndCELevelForCECapableUEs")
	if err := v.CellIdentifierAndCELevelForCECapableUEs.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	bb.LeaveComponent(toleranceMark_cellidentifierandcelevelforcecapableues)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.InformationForCECapableUEsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.InformationForCECapableUEsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeInformationForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CancelledCellinEAIItem to APER format.
func (v *CancelledCellinEAIItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CancelledCellinEAIItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.NumberOfBroadcasts), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding numberOfBroadcasts: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CancelledCellinEAIItem from APER format.
func (v *CancelledCellinEAIItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CancelledCellinEAIItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAIItem")
	}
	bb.EnterComponent("CancelledCellinEAIItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAIItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinEAIItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAIItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CancelledCellinEAIItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinEAIItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	val_numberofbroadcasts, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfBroadcasts")
	}
	v.NumberOfBroadcasts = s00.NumberOfBroadcasts(val_numberofbroadcasts)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CancelledCellinEAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CancelledCellinEAIItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCancelledCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CancelledCellinTAIItem to APER format.
func (v *CancelledCellinTAIItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CancelledCellinTAIItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.NumberOfBroadcasts), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding numberOfBroadcasts: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CancelledCellinTAIItem from APER format.
func (v *CancelledCellinTAIItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CancelledCellinTAIItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAIItem")
	}
	bb.EnterComponent("CancelledCellinTAIItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAIItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinTAIItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAIItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CancelledCellinTAIItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CancelledCellinTAIItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	val_numberofbroadcasts, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfBroadcasts")
	}
	v.NumberOfBroadcasts = s00.NumberOfBroadcasts(val_numberofbroadcasts)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CancelledCellinTAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CancelledCellinTAIItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCancelledCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CellIdentifierAndCELevelForCECapableUEs to APER format.
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.GlobalCellID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-Cell-ID: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.CELevel), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cELevel: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellIdentifierAndCELevelForCECapableUEs from APER format.
func (v *CellIdentifierAndCELevelForCECapableUEs) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIdentifierAndCELevelForCECapableUEs) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	bb.EnterComponent("CellIdentifierAndCELevelForCECapableUEs")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIdentifierAndCELevelForCECapableUEs")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	v.perPadding = padding
	return nil
}
func (v *CellIdentifierAndCELevelForCECapableUEs) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIdentifierAndCELevelForCECapableUEs{}
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
	toleranceMark_globalcellid := bb.EnterComponent("GlobalCellID")
	if err := v.GlobalCellID.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalCellID")
	}
	bb.LeaveComponent(toleranceMark_globalcellid)
	val_celevel, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CELevel")
	}
	v.CELevel = s00.CELevel(val_celevel)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CellIdentifierAndCELevelForCECapableUEsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CellIDBroadcastItem to APER format.
func (v *CellIDBroadcastItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellIDBroadcastItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellIDBroadcastItem from APER format.
func (v *CellIDBroadcastItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIDBroadcastItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcastItem")
	}
	bb.EnterComponent("CellIDBroadcastItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcastItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDBroadcastItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcastItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CellIDBroadcastItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDBroadcastItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CellIDBroadcastItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CellIDBroadcastItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCellIDBroadcastItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CellIDCancelledItem to APER format.
func (v *CellIDCancelledItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellIDCancelledItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.NumberOfBroadcasts), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding numberOfBroadcasts: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellIDCancelledItem from APER format.
func (v *CellIDCancelledItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIDCancelledItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelledItem")
	}
	bb.EnterComponent("CellIDCancelledItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelledItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDCancelledItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelledItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CellIDCancelledItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellIDCancelledItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	val_numberofbroadcasts, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfBroadcasts")
	}
	v.NumberOfBroadcasts = s00.NumberOfBroadcasts(val_numberofbroadcasts)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CellIDCancelledItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CellIDCancelledItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCellIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CompletedCellinEAIItem to APER format.
func (v *CompletedCellinEAIItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CompletedCellinEAIItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CompletedCellinEAIItem from APER format.
func (v *CompletedCellinEAIItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CompletedCellinEAIItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAIItem")
	}
	bb.EnterComponent("CompletedCellinEAIItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAIItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CompletedCellinEAIItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAIItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CompletedCellinEAIItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinEAIItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CompletedCellinEAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CompletedCellinEAIItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCompletedCellinEAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABUsageReportItem to APER format.
func (v *ERABUsageReportItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABUsageReportItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, v.StartTimestamp, 4, 4, true); err != nil {
		return fmt.Errorf("encoding startTimestamp: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, v.EndTimestamp, 4, 4, true); err != nil {
		return fmt.Errorf("encoding endTimestamp: %w", err)
	}
	if err := aper.EncodeIntegerUint64Aligned(bb, uint64(v.UsageCountUL), 0, 18446744073709551615, false); err != nil {
		return fmt.Errorf("encoding usageCountUL: %w", err)
	}
	if err := aper.EncodeIntegerUint64Aligned(bb, uint64(v.UsageCountDL), 0, 18446744073709551615, false); err != nil {
		return fmt.Errorf("encoding usageCountDL: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABUsageReportItem from APER format.
func (v *ERABUsageReportItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABUsageReportItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportItem")
	}
	bb.EnterComponent("ERABUsageReportItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABUsageReportItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABUsageReportItem")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABUsageReportItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABUsageReportItem{}
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
	val_starttimestamp, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "StartTimestamp")
	}
	v.StartTimestamp = val_starttimestamp
	val_endtimestamp, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EndTimestamp")
	}
	v.EndTimestamp = val_endtimestamp
	val_usagecountul, err := aper.DecodeIntegerUint64Aligned(bb, 0, 18446744073709551615, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UsageCountUL")
	}
	v.UsageCountUL = val_usagecountul
	val_usagecountdl, err := aper.DecodeIntegerUint64Aligned(bb, 0, 18446744073709551615, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UsageCountDL")
	}
	v.UsageCountDL = val_usagecountdl
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.ERABUsageReportItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.ERABUsageReportItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeERABUsageReportItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes EUTRANCGI to APER format.
func (v *EUTRANCGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EUTRANCGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNidentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMNidentity: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.CellID.Bytes, v.CellID.BitLength, 28, 28, true); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes EUTRANCGI from APER format.
func (v *EUTRANCGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EUTRANCGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANCGI")
	}
	bb.EnterComponent("EUTRANCGI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANCGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "EUTRANCGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANCGI")
	}
	v.perPadding = padding
	return nil
}
func (v *EUTRANCGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANCGI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNidentity")
	}
	v.PLMNidentity = s00.PLMNidentity(val_plmnidentity)
	bsBytes_cellid, bsBitLen_cellid, err := aper.DecodeBitStringAligned(bb, 28, 28, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = runtime.BitString{Bytes: bsBytes_cellid, BitLength: bsBitLen_cellid}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.EUTRANCGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.EUTRANCGIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeEUTRANCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CompletedCellinTAIItem to APER format.
func (v *CompletedCellinTAIItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CompletedCellinTAIItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.ECGI.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eCGI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CompletedCellinTAIItem from APER format.
func (v *CompletedCellinTAIItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CompletedCellinTAIItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAIItem")
	}
	bb.EnterComponent("CompletedCellinTAIItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAIItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CompletedCellinTAIItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAIItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CompletedCellinTAIItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CompletedCellinTAIItem{}
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
	toleranceMark_ecgi := bb.EnterComponent("ECGI")
	if err := v.ECGI.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECGI")
	}
	bb.LeaveComponent(toleranceMark_ecgi)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CompletedCellinTAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CompletedCellinTAIItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCompletedCellinTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *AssistanceDataForCECapableUEs) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceDataForCECapableUEs", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "AssistanceDataForCECapableUEs", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceDataForCECapableUEs) WithoutReplay() AssistanceDataForCECapableUEs {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero AssistanceDataForCECapableUEs
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinEAIItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinEAIItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinEAIItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinEAIItem) WithoutReplay() CancelledCellinEAIItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinEAIItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinTAIItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinTAIItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinTAIItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinTAIItem) WithoutReplay() CancelledCellinTAIItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinTAIItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDBroadcastItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDBroadcastItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDBroadcastItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDBroadcastItem) WithoutReplay() CellIDBroadcastItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDBroadcastItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDCancelledItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDCancelledItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDCancelledItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDCancelledItem) WithoutReplay() CellIDCancelledItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDCancelledItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIdentifierAndCELevelForCECapableUEs) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIdentifierAndCELevelForCECapableUEs", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIdentifierAndCELevelForCECapableUEs", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIdentifierAndCELevelForCECapableUEs) WithoutReplay() CellIdentifierAndCELevelForCECapableUEs {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIdentifierAndCELevelForCECapableUEs
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CompletedCellinEAIItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CompletedCellinEAIItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CompletedCellinEAIItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CompletedCellinEAIItem) WithoutReplay() CompletedCellinEAIItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CompletedCellinEAIItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CompletedCellinTAIItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CompletedCellinTAIItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CompletedCellinTAIItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CompletedCellinTAIItem) WithoutReplay() CompletedCellinTAIItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CompletedCellinTAIItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABUsageReportItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABUsageReportItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABUsageReportItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABUsageReportItem) WithoutReplay() ERABUsageReportItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABUsageReportItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EUTRANCGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EUTRANCGI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EUTRANCGI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EUTRANCGI) WithoutReplay() EUTRANCGI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EUTRANCGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceDataForCECapableUEs) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceDataForCECapableUEs) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForCECapableUEs.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForCECapableUEs.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceDataForCECapableUEs) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceDataForCECapableUEs.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceDataForCECapableUEs.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CancelledCellinEAIItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CancelledCellinEAIItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CancelledCellinEAIItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinEAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CancelledCellinEAIItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CancelledCellinEAIItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinEAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CancelledCellinTAIItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CancelledCellinTAIItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CancelledCellinTAIItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinTAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CancelledCellinTAIItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CancelledCellinTAIItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinTAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellIDBroadcastItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellIDBroadcastItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIDBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellIDBroadcastItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIDBroadcastItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDBroadcastItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellIDCancelledItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellIDCancelledItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellIDCancelledItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellIdentifierAndCELevelForCECapableUEs) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellIdentifierAndCELevelForCECapableUEs) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIdentifierAndCELevelForCECapableUEs.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdentifierAndCELevelForCECapableUEs.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellIdentifierAndCELevelForCECapableUEs) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellIdentifierAndCELevelForCECapableUEs.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdentifierAndCELevelForCECapableUEs.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CompletedCellinEAIItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CompletedCellinEAIItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CompletedCellinEAIItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinEAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CompletedCellinEAIItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CompletedCellinEAIItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinEAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CompletedCellinTAIItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CompletedCellinTAIItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CompletedCellinTAIItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinTAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CompletedCellinTAIItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CompletedCellinTAIItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CompletedCellinTAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABUsageReportItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABUsageReportItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABUsageReportItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABUsageReportItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABUsageReportItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABUsageReportItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABUsageReportItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EUTRANCGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EUTRANCGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANCGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EUTRANCGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANCGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *AssistanceDataForCECapableUEs) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "AssistanceDataForCECapableUEs")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *AssistanceDataForCECapableUEs) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForCECapableUEs")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APAssistanceDataForCECapableUEs(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "AssistanceDataForCECapableUEs")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "AssistanceDataForCECapableUEs")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *AssistanceDataForCECapableUEs) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "AssistanceDataForCECapableUEs")
}
func (v *AssistanceDataForCECapableUEs) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "AssistanceDataForCECapableUEs")
}
func (v *AssistanceDataForCECapableUEs) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APAssistanceDataForCECapableUEs(v, &s)
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
func (v *AssistanceDataForCECapableUEs) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *AssistanceDataForCECapableUEs) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CancelledCellinEAIItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinEAIItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinEAIItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinEAIItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinEAIItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinEAIItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinEAIItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinEAIItem")
}
func (v *CancelledCellinEAIItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinEAIItem")
}
func (v *CancelledCellinEAIItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinEAIItem(v, &s)
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
func (v *CancelledCellinEAIItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinEAIItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CancelledCellinTAIItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinTAIItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinTAIItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinTAIItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinTAIItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinTAIItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinTAIItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinTAIItem")
}
func (v *CancelledCellinTAIItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinTAIItem")
}
func (v *CancelledCellinTAIItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinTAIItem(v, &s)
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
func (v *CancelledCellinTAIItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinTAIItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellIDBroadcastItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDBroadcastItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDBroadcastItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDBroadcastItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDBroadcastItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDBroadcastItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDBroadcastItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDBroadcastItem")
}
func (v *CellIDBroadcastItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDBroadcastItem")
}
func (v *CellIDBroadcastItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDBroadcastItem(v, &s)
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
func (v *CellIDBroadcastItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDBroadcastItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellIDCancelledItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDCancelledItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDCancelledItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDCancelledItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDCancelledItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDCancelledItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDCancelledItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDCancelledItem")
}
func (v *CellIDCancelledItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDCancelledItem")
}
func (v *CellIDCancelledItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDCancelledItem(v, &s)
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
func (v *CellIDCancelledItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDCancelledItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellIdentifierAndCELevelForCECapableUEs) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIdentifierAndCELevelForCECapableUEs")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIdentifierAndCELevelForCECapableUEs")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIdentifierAndCELevelForCECapableUEs")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIdentifierAndCELevelForCECapableUEs")
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIdentifierAndCELevelForCECapableUEs")
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIdentifierAndCELevelForCECapableUEs(v, &s)
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
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIdentifierAndCELevelForCECapableUEs) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CompletedCellinEAIItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CompletedCellinEAIItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CompletedCellinEAIItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinEAIItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCompletedCellinEAIItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CompletedCellinEAIItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CompletedCellinEAIItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CompletedCellinEAIItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CompletedCellinEAIItem")
}
func (v *CompletedCellinEAIItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CompletedCellinEAIItem")
}
func (v *CompletedCellinEAIItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCompletedCellinEAIItem(v, &s)
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
func (v *CompletedCellinEAIItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CompletedCellinEAIItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CompletedCellinTAIItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CompletedCellinTAIItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CompletedCellinTAIItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinTAIItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCompletedCellinTAIItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CompletedCellinTAIItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CompletedCellinTAIItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CompletedCellinTAIItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CompletedCellinTAIItem")
}
func (v *CompletedCellinTAIItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CompletedCellinTAIItem")
}
func (v *CompletedCellinTAIItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCompletedCellinTAIItem(v, &s)
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
func (v *CompletedCellinTAIItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CompletedCellinTAIItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABUsageReportItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABUsageReportItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABUsageReportItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABUsageReportItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABUsageReportItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABUsageReportItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABUsageReportItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABUsageReportItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABUsageReportItem")
}
func (v *ERABUsageReportItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABUsageReportItem")
}
func (v *ERABUsageReportItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABUsageReportItem(v, &s)
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
func (v *ERABUsageReportItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABUsageReportItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EUTRANCGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EUTRANCGI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EUTRANCGI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EUTRANCGI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEUTRANCGI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EUTRANCGI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EUTRANCGI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EUTRANCGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EUTRANCGI")
}
func (v *EUTRANCGI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EUTRANCGI")
}
func (v *EUTRANCGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEUTRANCGI(v, &s)
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
func (v *EUTRANCGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EUTRANCGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *AssistanceDataForCECapableUEs) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceDataForCECapableUEs")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded AssistanceDataForCECapableUEs
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APAssistanceDataForCECapableUEs(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = AssistanceDataForCECapableUEs{}
		return report, aper.OperationError(err, "AssistanceDataForCECapableUEs")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceDataForCECapableUEs")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinEAIItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinEAIItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinEAIItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinEAIItem{}
		return report, aper.OperationError(err, "CancelledCellinEAIItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinEAIItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinTAIItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinTAIItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinTAIItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinTAIItem{}
		return report, aper.OperationError(err, "CancelledCellinTAIItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinTAIItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDBroadcastItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDBroadcastItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDBroadcastItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDBroadcastItem{}
		return report, aper.OperationError(err, "CellIDBroadcastItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDBroadcastItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDCancelledItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDCancelledItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDCancelledItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDCancelledItem{}
		return report, aper.OperationError(err, "CellIDCancelledItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDCancelledItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIdentifierAndCELevelForCECapableUEs) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIdentifierAndCELevelForCECapableUEs")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIdentifierAndCELevelForCECapableUEs
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIdentifierAndCELevelForCECapableUEs(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIdentifierAndCELevelForCECapableUEs{}
		return report, aper.OperationError(err, "CellIdentifierAndCELevelForCECapableUEs")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIdentifierAndCELevelForCECapableUEs")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CompletedCellinEAIItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinEAIItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CompletedCellinEAIItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCompletedCellinEAIItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CompletedCellinEAIItem{}
		return report, aper.OperationError(err, "CompletedCellinEAIItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CompletedCellinEAIItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CompletedCellinTAIItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinTAIItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CompletedCellinTAIItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCompletedCellinTAIItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CompletedCellinTAIItem{}
		return report, aper.OperationError(err, "CompletedCellinTAIItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CompletedCellinTAIItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABUsageReportItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABUsageReportItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABUsageReportItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABUsageReportItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABUsageReportItem{}
		return report, aper.OperationError(err, "ERABUsageReportItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABUsageReportItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EUTRANCGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EUTRANCGI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EUTRANCGI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEUTRANCGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EUTRANCGI{}
		return report, aper.OperationError(err, "EUTRANCGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EUTRANCGI")
}

type ERABSubjecttoDataForwardingList = []s18.ERABDataForwardingItemIEValueProtocolIESingleContainer
type ERABToBeSwitchedULList = []ERABToBeSwitchedULItemIEValueProtocolIESingleContainer

// ERABToBeSwitchedULItem represents the ASN.1 type E-RABToBeSwitchedULItem (SEQUENCE).
type ERABToBeSwitchedULItem struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	ERABID                s00.ERABID                                   `asn1:"tag:0,context,implicit"`
	TransportLayerAddress s00.TransportLayerAddress                    `asn1:"tag:1,context,implicit"`
	GTPTEID               s00.GTPTEID                                  `asn1:"tag:2,context,implicit"`
	IEExtensions          s10.ERABToBeSwitchedULItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                         `asn1:"-" json:"-"`
	extCount              int64                                        `asn1:"-" json:"-"`
	extPresent            []bool                                       `asn1:"-" json:"-"`
	extData               [][]byte                                     `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type ERABSetupListBearerSURes = []s19.ERABSetupItemBearerSUResIEValueProtocolIESingleContainer
type ERABSetupListCtxtSURes = []s19.ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer
type ERABToBeModifiedListBearerModInd = []ERABToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABToBeModifiedItemBearerModInd represents the ASN.1 type E-RABToBeModifiedItemBearerModInd (SEQUENCE).
type ERABToBeModifiedItemBearerModInd struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	ERABID                s00.ERABID                                             `asn1:"tag:0,context,implicit"`
	TransportLayerAddress s00.TransportLayerAddress                              `asn1:"tag:1,context,implicit"`
	DLGTPTEID             s00.GTPTEID                                            `asn1:"tag:2,context,implicit"`
	IEExtensions          s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                                   `asn1:"-" json:"-"`
	extCount              int64                                                  `asn1:"-" json:"-"`
	extPresent            []bool                                                 `asn1:"-" json:"-"`
	extData               [][]byte                                               `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// MarshalAPER encodes ERABToBeSwitchedULItem to APER format.
func (v *ERABToBeSwitchedULItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeSwitchedULItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.GTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding gTP-TEID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeSwitchedULItem from APER format.
func (v *ERABToBeSwitchedULItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABToBeSwitchedULItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
	}
	bb.EnterComponent("ERABToBeSwitchedULItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeSwitchedULItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABToBeSwitchedULItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeSwitchedULItem{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_gtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "GTPTEID")
	}
	v.GTPTEID = s00.GTPTEID(val_gtpteid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.ERABToBeSwitchedULItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.ERABToBeSwitchedULItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeERABToBeSwitchedULItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ERABToBeModifiedItemBearerModInd to APER format.
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.DLGTPTEID), 4, 4, true); err != nil {
		return fmt.Errorf("encoding dL-GTP-TEID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABToBeModifiedItemBearerModInd from APER format.
func (v *ERABToBeModifiedItemBearerModInd) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABToBeModifiedItemBearerModInd) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
	}
	bb.EnterComponent("ERABToBeModifiedItemBearerModInd")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABToBeModifiedItemBearerModInd")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
	}
	v.perPadding = padding
	return nil
}
func (v *ERABToBeModifiedItemBearerModInd) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABToBeModifiedItemBearerModInd{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	val_dlgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "DLGTPTEID")
	}
	v.DLGTPTEID = s00.GTPTEID(val_dlgtpteid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.ERABToBeModifiedItemBearerModIndExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.ERABToBeModifiedItemBearerModIndExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeERABToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeModifiedItemBearerModInd) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeModifiedItemBearerModInd", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeModifiedItemBearerModInd", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeModifiedItemBearerModInd) WithoutReplay() ERABToBeModifiedItemBearerModInd {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeModifiedItemBearerModInd
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABToBeSwitchedULItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABToBeSwitchedULItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABToBeSwitchedULItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABToBeSwitchedULItem) WithoutReplay() ERABToBeSwitchedULItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABToBeSwitchedULItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeModifiedItemBearerModInd) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeModifiedItemBearerModInd) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeModifiedItemBearerModInd) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABToBeSwitchedULItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABToBeSwitchedULItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSwitchedULItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSwitchedULItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABToBeSwitchedULItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABToBeSwitchedULItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABToBeSwitchedULItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABToBeModifiedItemBearerModInd) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeModifiedItemBearerModInd")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedItemBearerModInd")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeModifiedItemBearerModInd(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeModifiedItemBearerModInd")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModInd")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModInd")
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeModifiedItemBearerModInd")
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeModifiedItemBearerModInd(v, &s)
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
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeModifiedItemBearerModInd) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeSwitchedULItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABToBeSwitchedULItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABToBeSwitchedULItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedULItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABToBeSwitchedULItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABToBeSwitchedULItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABToBeSwitchedULItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABToBeSwitchedULItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABToBeSwitchedULItem")
}
func (v *ERABToBeSwitchedULItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABToBeSwitchedULItem")
}
func (v *ERABToBeSwitchedULItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABToBeSwitchedULItem(v, &s)
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
func (v *ERABToBeSwitchedULItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABToBeSwitchedULItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABToBeModifiedItemBearerModInd) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeModifiedItemBearerModInd")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeModifiedItemBearerModInd
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeModifiedItemBearerModInd(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeModifiedItemBearerModInd{}
		return report, aper.OperationError(err, "ERABToBeModifiedItemBearerModInd")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeModifiedItemBearerModInd")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABToBeSwitchedULItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABToBeSwitchedULItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABToBeSwitchedULItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABToBeSwitchedULItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABToBeSwitchedULItem{}
		return report, aper.OperationError(err, "ERABToBeSwitchedULItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABToBeSwitchedULItem")
}

type ERABUsageReportItemIEValue struct {
	id                     s00.ProtocolIEID
	received               aper.WireSpan
	replay                 aper.Snapshot
	opaque                 aper.OpaqueOpenType
	isOpaque               bool
	rowERABUsageReportItem *ERABUsageReportItem
}

func (v ERABUsageReportItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(267):
		return v.rowERABUsageReportItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABUsageReportItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABUsageReportItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABUsageReportItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABUsageReportItemIEs"}}
}
func (ERABUsageReportItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(267):
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

// AsERABUsageReportItem returns the selected ERABUsageReportItem value of ERABUsageReportItemIEValue and reports whether that alternative is active.
func (v *ERABUsageReportItemIEValue) AsERABUsageReportItem() (*ERABUsageReportItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(267) || v.rowERABUsageReportItem == nil {
		return nil, false
	}
	return v.rowERABUsageReportItem, true
}
func (v ERABUsageReportItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABUsageReportItemIEValue, error) {
	out := ERABUsageReportItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(267):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABUsageReportItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABUsageReportItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABUsageReportItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABUsageReportItem = &value
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
func (v ERABUsageReportItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABUsageReportItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(267):
		if v.rowERABUsageReportItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABUsageReportItemIEs.id-E-RABUsageReportItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABUsageReportItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABUsageReportItemIEValue:", v.id)
	}
}

type CellTrafficTraceIEValue struct {
	id                                s00.ProtocolIEID
	received                          aper.WireSpan
	replay                            aper.Snapshot
	opaque                            aper.OpaqueOpenType
	isOpaque                          bool
	rowMMEUES1APID                    *s00.MMEUES1APID
	rowENBUES1APID                    *s00.ENBUES1APID
	rowEUTRANTraceID                  *s00.EUTRANTraceID
	rowEUTRANCGI                      *EUTRANCGI
	rowTraceCollectionEntityIPAddress *s00.TransportLayerAddress
	rowPrivacyIndicator               *s00.PrivacyIndicator
}

func (v CellTrafficTraceIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(86):
		return v.rowEUTRANTraceID != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(131):
		return v.rowTraceCollectionEntityIPAddress != nil
	case s00.ProtocolIEID(166):
		return v.rowPrivacyIndicator != nil
	}
	return false
}

// Opaque returns the retained opaque open value of CellTrafficTraceIEValue and reports whether the opaque alternative is selected.
func (v *CellTrafficTraceIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CellTrafficTraceIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CellTrafficTraceIEs"}}
}
func (CellTrafficTraceIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(86):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(131):
		return aper.UnknownSelector
	case s00.ProtocolIEID(166):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsEUTRANTraceID returns the selected EUTRANTraceID value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsEUTRANTraceID() (*s00.EUTRANTraceID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(86) || v.rowEUTRANTraceID == nil {
		return nil, false
	}
	return v.rowEUTRANTraceID, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsEUTRANCGI() (*EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTraceCollectionEntityIPAddress returns the selected TraceCollectionEntityIPAddress value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsTraceCollectionEntityIPAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(131) || v.rowTraceCollectionEntityIPAddress == nil {
		return nil, false
	}
	return v.rowTraceCollectionEntityIPAddress, true
}

// AsPrivacyIndicator returns the selected PrivacyIndicator value of CellTrafficTraceIEValue and reports whether that alternative is active.
func (v *CellTrafficTraceIEValue) AsPrivacyIndicator() (*s00.PrivacyIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(166) || v.rowPrivacyIndicator == nil {
		return nil, false
	}
	return v.rowPrivacyIndicator, true
}
func (v CellTrafficTraceIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CellTrafficTraceIEValue, error) {
	out := CellTrafficTraceIEValue{id: id}
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
	case s00.ProtocolIEID(86):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.EUTRANTraceID, error) {
			var v struct{ Value s00.EUTRANTraceID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 8, 8, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.EUTRANTraceID(val_value)
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
		out.rowEUTRANTraceID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value EUTRANCGI
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(131):
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
		out.rowTraceCollectionEntityIPAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(166):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PrivacyIndicator"})
		value := s00.PrivacyIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PrivacyIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPrivacyIndicator = &value
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
func (v CellTrafficTraceIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v CellTrafficTraceIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(86):
		if v.rowEUTRANTraceID == nil {
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-E-UTRAN-Trace-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.EUTRANTraceID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.EUTRANTraceID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 8, 8, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowEUTRANTraceID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-EUTRAN-CGI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowEUTRANCGI.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(131):
		if v.rowTraceCollectionEntityIPAddress == nil {
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-TraceCollectionEntityIPAddress:")
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
		})(*v.rowTraceCollectionEntityIPAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(166):
		if v.rowPrivacyIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "CellTrafficTraceIEs.id-PrivacyIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPrivacyIndicator), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CellTrafficTraceIEValue:", v.id)
	}
}

type ERABToBeModifiedItemBearerModIndIEValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowERABToBeModifiedItemBearerModInd *ERABToBeModifiedItemBearerModInd
}

func (v ERABToBeModifiedItemBearerModIndIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(200):
		return v.rowERABToBeModifiedItemBearerModInd != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeModifiedItemBearerModIndIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeModifiedItemBearerModIndIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeModifiedItemBearerModIndIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModIndIEs"}}
}
func (ERABToBeModifiedItemBearerModIndIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(200):
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

// AsERABToBeModifiedItemBearerModInd returns the selected ERABToBeModifiedItemBearerModInd value of ERABToBeModifiedItemBearerModIndIEValue and reports whether that alternative is active.
func (v *ERABToBeModifiedItemBearerModIndIEValue) AsERABToBeModifiedItemBearerModInd() (*ERABToBeModifiedItemBearerModInd, bool) {
	if v == nil || v.id != s00.ProtocolIEID(200) || v.rowERABToBeModifiedItemBearerModInd == nil {
		return nil, false
	}
	return v.rowERABToBeModifiedItemBearerModInd, true
}
func (v ERABToBeModifiedItemBearerModIndIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeModifiedItemBearerModIndIEValue, error) {
	out := ERABToBeModifiedItemBearerModIndIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(200):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeModifiedItemBearerModInd
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeModifiedItemBearerModInd:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeModifiedItemBearerModInd")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeModifiedItemBearerModInd = &value
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
func (v ERABToBeModifiedItemBearerModIndIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABToBeModifiedItemBearerModIndIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(200):
		if v.rowERABToBeModifiedItemBearerModInd == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeModifiedItemBearerModIndIEs.id-E-RABToBeModifiedItemBearerModInd:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeModifiedItemBearerModInd.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeModifiedItemBearerModIndIEValue:", v.id)
	}
}

type ERABToBeSwitchedULItemIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABToBeSwitchedULItem *ERABToBeSwitchedULItem
}

func (v ERABToBeSwitchedULItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(94):
		return v.rowERABToBeSwitchedULItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABToBeSwitchedULItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABToBeSwitchedULItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABToBeSwitchedULItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULItemIEs"}}
}
func (ERABToBeSwitchedULItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(94):
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

// AsERABToBeSwitchedULItem returns the selected ERABToBeSwitchedULItem value of ERABToBeSwitchedULItemIEValue and reports whether that alternative is active.
func (v *ERABToBeSwitchedULItemIEValue) AsERABToBeSwitchedULItem() (*ERABToBeSwitchedULItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(94) || v.rowERABToBeSwitchedULItem == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedULItem, true
}
func (v ERABToBeSwitchedULItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABToBeSwitchedULItemIEValue, error) {
	out := ERABToBeSwitchedULItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(94):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABToBeSwitchedULItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedULItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABToBeSwitchedULItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABToBeSwitchedULItem = &value
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
func (v ERABToBeSwitchedULItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABToBeSwitchedULItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(94):
		if v.rowERABToBeSwitchedULItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABToBeSwitchedULItemIEs.id-E-RABToBeSwitchedULItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABToBeSwitchedULItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABToBeSwitchedULItemIEValue:", v.id)
	}
}

type ERABUsageReportItemIETable struct{}

func ERABUsageReportItemIEs() ERABUsageReportItemIETable { return ERABUsageReportItemIETable{} }

// ID returns the ASN.1 object-set identity of ERABUsageReportItemIETable.
func (ERABUsageReportItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABUsageReportItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABUsageReportItemIETable.
func (ERABUsageReportItemIETable) Table() s00.ERABUsageReportItemIEValueIETable {
	return func() s00.ERABUsageReportItemIEValueIETable {
		sealed := s00.ERABUsageReportItemIEValueIETable{}
		*s00.BridgeERABUsageReportItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABUsageReportItemIETable) infoERABUsageReportItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABUsageReportItemIEs().ID(), ID: s00.ProtocolIEID(267), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABUsageReportItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABUsageReportItemIEs", Row: "id-E-RABUsageReportItem"}}}
}

// ERABUsageReportItem returns the typed binding for the ERABUsageReportItem row of ERABUsageReportItemIETable.
func (t ERABUsageReportItemIETable) ERABUsageReportItem() ERABUsageReportItemERABUsageReportItemIEBinding {
	return ERABUsageReportItemERABUsageReportItemIEBinding{info: t.infoERABUsageReportItem(), codec: ERABUsageReportItemValueCodec{path: "ERABUsageReportItem",
		decode: func(data []byte, options aper.DecodeState) (ERABUsageReportItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABUsageReportItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABUsageReportItem")
			var zero ERABUsageReportItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(267), raw)
			if err != nil {
				var empty ERABUsageReportItem
				return empty, runtime.WrapDecodePath(err, "ERABUsageReportItem")
			}
			value, ok := decoded.AsERABUsageReportItem()
			if !ok {
				var empty ERABUsageReportItem
				return empty, fmt.Errorf("binding E-RABUsageReportItemIEs.id-E-RABUsageReportItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABUsageReportItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABUsageReportItemIEValue{id: s00.ProtocolIEID(267), rowERABUsageReportItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABUsageReportItem, options aper.DecodeState) (ERABUsageReportItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABUsageReportItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABUsageReportItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABUsageReportItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABUsageReportItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABUsageReportItem) ERABUsageReportItemIEValue {
		return ERABUsageReportItemIEValue{id: s00.ProtocolIEID(267), rowERABUsageReportItem: &value}
	}, get: func(value *ERABUsageReportItemIEValue) (*ERABUsageReportItem, bool) {
		return value.AsERABUsageReportItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABUsageReportItemIETable.
func (t ERABUsageReportItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABUsageReportItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(267):
		return ERABUsageReportItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABUsageReportItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABUsageReportItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABUsageReportItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABUsageReportItemIEField{Id: id, Criticality: criticality, Value: ERABUsageReportItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupItemCtxtSUResIETable struct{}

func ERABSetupItemCtxtSUResIEs() ERABSetupItemCtxtSUResIETable {
	return ERABSetupItemCtxtSUResIETable{}
}

// ID returns the ASN.1 object-set identity of ERABSetupItemCtxtSUResIETable.
func (ERABSetupItemCtxtSUResIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSUResIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABSetupItemCtxtSUResIETable.
func (ERABSetupItemCtxtSUResIETable) Table() s00.ERABSetupItemCtxtSUResIEValueIETable {
	return func() s00.ERABSetupItemCtxtSUResIEValueIETable {
		sealed := s00.ERABSetupItemCtxtSUResIEValueIETable{}
		*s00.BridgeERABSetupItemCtxtSUResIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSetupItemCtxtSUResIETable) infoERABSetupItemCtxtSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupItemCtxtSUResIEs().ID(), ID: s00.ProtocolIEID(50), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSURes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSUResIEs", Row: "id-E-RABSetupItemCtxtSURes"}}}
}

// ERABSetupItemCtxtSURes returns the typed binding for the ERABSetupItemCtxtSURes row of ERABSetupItemCtxtSUResIETable.
func (t ERABSetupItemCtxtSUResIETable) ERABSetupItemCtxtSURes() s19.ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding {
	return func() s19.ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding {
		sealed := s19.ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding{}
		*s19.BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldInfo(&sealed) = t.infoERABSetupItemCtxtSURes()
		*s19.BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldCodec(&sealed) = func() s19.ERABSetupItemCtxtSUResValueCodec {
			sealed := s19.ERABSetupItemCtxtSUResValueCodec{}
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldPath(&sealed) = "ERABSetupItemCtxtSURes"
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABSetupItemCtxtSURes, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.ERABSetupItemCtxtSURes
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABSetupItemCtxtSURes")
				var zero s19.ERABSetupItemCtxtSUResIEValue
				decoded, err := s19.BridgeERABSetupItemCtxtSUResIEValueMethodDecode(zero, s00.ProtocolIEID(50), raw)
				if err != nil {
					var empty s19.ERABSetupItemCtxtSURes
					return empty, runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
				}
				value, ok := decoded.AsERABSetupItemCtxtSURes()
				if !ok {
					var empty s19.ERABSetupItemCtxtSURes
					return empty, fmt.Errorf("binding E-RABSetupItemCtxtSUResIEs.id-E-RABSetupItemCtxtSURes: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldEncode(&sealed) = func(value s19.ERABSetupItemCtxtSURes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s19.BridgeERABSetupItemCtxtSUResIEValueMethodEncodeFresh((func() s19.ERABSetupItemCtxtSUResIEValue {
					sealed := s19.ERABSetupItemCtxtSUResIEValue{}
					*s19.BridgeERABSetupItemCtxtSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(50)
					*s19.BridgeERABSetupItemCtxtSUResIEValueFieldRowERABSetupItemCtxtSURes(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldCapture(&sealed) = func(v s19.ERABSetupItemCtxtSURes, options aper.DecodeState) (s19.ERABSetupItemCtxtSURes, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APERABSetupItemCtxtSURes(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldCompare(&sealed) = func(v s19.ERABSetupItemCtxtSURes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APERABSetupItemCtxtSURes(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeERABSetupItemCtxtSUResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupItemCtxtSURes"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s19.BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldInject(&sealed) = func(value s19.ERABSetupItemCtxtSURes) s19.ERABSetupItemCtxtSUResIEValue {
			return func() s19.ERABSetupItemCtxtSUResIEValue {
				sealed := s19.ERABSetupItemCtxtSUResIEValue{}
				*s19.BridgeERABSetupItemCtxtSUResIEValueFieldId(&sealed) = s00.ProtocolIEID(50)
				*s19.BridgeERABSetupItemCtxtSUResIEValueFieldRowERABSetupItemCtxtSURes(&sealed) = &value
				return sealed
			}()
		}
		*s19.BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldGet(&sealed) = func(value *s19.ERABSetupItemCtxtSUResIEValue) (*s19.ERABSetupItemCtxtSURes, bool) {
			return value.AsERABSetupItemCtxtSURes()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABSetupItemCtxtSUResIETable.
func (t ERABSetupItemCtxtSUResIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s19.ERABSetupItemCtxtSUResIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s19.ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(50):
		return s19.ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSetupItemCtxtSURes requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s19.ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s19.ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		return s19.ERABSetupItemCtxtSUResIEField{Id: id, Criticality: criticality, Value: func() s19.ERABSetupItemCtxtSUResIEValue {
			sealed := s19.ERABSetupItemCtxtSUResIEValue{}
			*s19.BridgeERABSetupItemCtxtSUResIEValueFieldId(&sealed) = id
			*s19.BridgeERABSetupItemCtxtSUResIEValueFieldOpaque(&sealed) = opaque
			*s19.BridgeERABSetupItemCtxtSUResIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeModifiedItemBearerModIndIETable struct{}

func ERABToBeModifiedItemBearerModIndIEs() ERABToBeModifiedItemBearerModIndIETable {
	return ERABToBeModifiedItemBearerModIndIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeModifiedItemBearerModIndIETable.
func (ERABToBeModifiedItemBearerModIndIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModIndIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeModifiedItemBearerModIndIETable.
func (ERABToBeModifiedItemBearerModIndIETable) Table() s00.ERABToBeModifiedItemBearerModIndIEValueIETable {
	return func() s00.ERABToBeModifiedItemBearerModIndIEValueIETable {
		sealed := s00.ERABToBeModifiedItemBearerModIndIEValueIETable{}
		*s00.BridgeERABToBeModifiedItemBearerModIndIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeModifiedItemBearerModIndIETable) infoERABToBeModifiedItemBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeModifiedItemBearerModIndIEs().ID(), ID: s00.ProtocolIEID(200), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeModifiedItemBearerModIndIEs", Row: "id-E-RABToBeModifiedItemBearerModInd"}}}
}

// ERABToBeModifiedItemBearerModInd returns the typed binding for the ERABToBeModifiedItemBearerModInd row of ERABToBeModifiedItemBearerModIndIETable.
func (t ERABToBeModifiedItemBearerModIndIETable) ERABToBeModifiedItemBearerModInd() ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding {
	return ERABToBeModifiedItemBearerModIndERABToBeModifiedItemBearerModIndIEBinding{info: t.infoERABToBeModifiedItemBearerModInd(), codec: ERABToBeModifiedItemBearerModIndValueCodec{path: "ERABToBeModifiedItemBearerModInd",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeModifiedItemBearerModInd, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeModifiedItemBearerModInd
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeModifiedItemBearerModInd")
			var zero ERABToBeModifiedItemBearerModIndIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(200), raw)
			if err != nil {
				var empty ERABToBeModifiedItemBearerModInd
				return empty, runtime.WrapDecodePath(err, "ERABToBeModifiedItemBearerModInd")
			}
			value, ok := decoded.AsERABToBeModifiedItemBearerModInd()
			if !ok {
				var empty ERABToBeModifiedItemBearerModInd
				return empty, fmt.Errorf("binding E-RABToBeModifiedItemBearerModIndIEs.id-E-RABToBeModifiedItemBearerModInd: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeModifiedItemBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeModifiedItemBearerModIndIEValue{id: s00.ProtocolIEID(200), rowERABToBeModifiedItemBearerModInd: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeModifiedItemBearerModInd, options aper.DecodeState) (ERABToBeModifiedItemBearerModInd, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeModifiedItemBearerModInd(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeModifiedItemBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeModifiedItemBearerModInd(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeModifiedItemBearerModInd"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeModifiedItemBearerModInd) ERABToBeModifiedItemBearerModIndIEValue {
		return ERABToBeModifiedItemBearerModIndIEValue{id: s00.ProtocolIEID(200), rowERABToBeModifiedItemBearerModInd: &value}
	}, get: func(value *ERABToBeModifiedItemBearerModIndIEValue) (*ERABToBeModifiedItemBearerModInd, bool) {
		return value.AsERABToBeModifiedItemBearerModInd()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeModifiedItemBearerModIndIETable.
func (t ERABToBeModifiedItemBearerModIndIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeModifiedItemBearerModIndIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(200):
		return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeModifiedItemBearerModInd requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeModifiedItemBearerModIndIEField{Id: id, Criticality: criticality, Value: ERABToBeModifiedItemBearerModIndIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABToBeSwitchedULItemIETable struct{}

func ERABToBeSwitchedULItemIEs() ERABToBeSwitchedULItemIETable {
	return ERABToBeSwitchedULItemIETable{}
}

// ID returns the ASN.1 object-set identity of ERABToBeSwitchedULItemIETable.
func (ERABToBeSwitchedULItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABToBeSwitchedULItemIETable.
func (ERABToBeSwitchedULItemIETable) Table() s00.ERABToBeSwitchedULItemIEValueIETable {
	return func() s00.ERABToBeSwitchedULItemIEValueIETable {
		sealed := s00.ERABToBeSwitchedULItemIEValueIETable{}
		*s00.BridgeERABToBeSwitchedULItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABToBeSwitchedULItemIETable) infoERABToBeSwitchedULItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABToBeSwitchedULItemIEs().ID(), ID: s00.ProtocolIEID(94), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULItemIEs", Row: "id-E-RABToBeSwitchedULItem"}}}
}

// ERABToBeSwitchedULItem returns the typed binding for the ERABToBeSwitchedULItem row of ERABToBeSwitchedULItemIETable.
func (t ERABToBeSwitchedULItemIETable) ERABToBeSwitchedULItem() ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding {
	return ERABToBeSwitchedULItemERABToBeSwitchedULItemIEBinding{info: t.infoERABToBeSwitchedULItem(), codec: ERABToBeSwitchedULItemValueCodec{path: "ERABToBeSwitchedULItem",
		decode: func(data []byte, options aper.DecodeState) (ERABToBeSwitchedULItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABToBeSwitchedULItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSwitchedULItem")
			var zero ERABToBeSwitchedULItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(94), raw)
			if err != nil {
				var empty ERABToBeSwitchedULItem
				return empty, runtime.WrapDecodePath(err, "ERABToBeSwitchedULItem")
			}
			value, ok := decoded.AsERABToBeSwitchedULItem()
			if !ok {
				var empty ERABToBeSwitchedULItem
				return empty, fmt.Errorf("binding E-RABToBeSwitchedULItemIEs.id-E-RABToBeSwitchedULItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABToBeSwitchedULItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABToBeSwitchedULItemIEValue{id: s00.ProtocolIEID(94), rowERABToBeSwitchedULItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABToBeSwitchedULItem, options aper.DecodeState) (ERABToBeSwitchedULItem, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABToBeSwitchedULItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABToBeSwitchedULItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABToBeSwitchedULItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedULItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABToBeSwitchedULItem) ERABToBeSwitchedULItemIEValue {
		return ERABToBeSwitchedULItemIEValue{id: s00.ProtocolIEID(94), rowERABToBeSwitchedULItem: &value}
	}, get: func(value *ERABToBeSwitchedULItemIEValue) (*ERABToBeSwitchedULItem, bool) {
		return value.AsERABToBeSwitchedULItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABToBeSwitchedULItemIETable.
func (t ERABToBeSwitchedULItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABToBeSwitchedULItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(94):
		return ERABToBeSwitchedULItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedULItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABToBeSwitchedULItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABToBeSwitchedULItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABToBeSwitchedULItemIEField{Id: id, Criticality: criticality, Value: ERABToBeSwitchedULItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AssistanceDataForCECapableUEsCodec binds the complete source value type.
func AssistanceDataForCECapableUEsCodec() AssistanceDataForCECapableUEsValueCodec {
	return AssistanceDataForCECapableUEsValueCodec{path: "AssistanceDataForCECapableUEs", decode: func(data []byte, options aper.DecodeState) (AssistanceDataForCECapableUEs, error) {
		var value AssistanceDataForCECapableUEs
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return AssistanceDataForCECapableUEs{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value AssistanceDataForCECapableUEs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v AssistanceDataForCECapableUEs, options aper.DecodeState) (AssistanceDataForCECapableUEs, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APAssistanceDataForCECapableUEs(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v AssistanceDataForCECapableUEs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APAssistanceDataForCECapableUEs(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceDataForCECapableUEs"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CancelledCellinEAIItemCodec binds the complete source value type.
func CancelledCellinEAIItemCodec() CancelledCellinEAIItemValueCodec {
	return CancelledCellinEAIItemValueCodec{path: "CancelledCellinEAIItem", decode: func(data []byte, options aper.DecodeState) (CancelledCellinEAIItem, error) {
		var value CancelledCellinEAIItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CancelledCellinEAIItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CancelledCellinEAIItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CancelledCellinEAIItem, options aper.DecodeState) (CancelledCellinEAIItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCancelledCellinEAIItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CancelledCellinEAIItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCancelledCellinEAIItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinEAIItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CancelledCellinTAIItemCodec binds the complete source value type.
func CancelledCellinTAIItemCodec() CancelledCellinTAIItemValueCodec {
	return CancelledCellinTAIItemValueCodec{path: "CancelledCellinTAIItem", decode: func(data []byte, options aper.DecodeState) (CancelledCellinTAIItem, error) {
		var value CancelledCellinTAIItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CancelledCellinTAIItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CancelledCellinTAIItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CancelledCellinTAIItem, options aper.DecodeState) (CancelledCellinTAIItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCancelledCellinTAIItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CancelledCellinTAIItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCancelledCellinTAIItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinTAIItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellIDBroadcastItemCodec binds the complete source value type.
func CellIDBroadcastItemCodec() CellIDBroadcastItemValueCodec {
	return CellIDBroadcastItemValueCodec{path: "CellIDBroadcastItem", decode: func(data []byte, options aper.DecodeState) (CellIDBroadcastItem, error) {
		var value CellIDBroadcastItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellIDBroadcastItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellIDBroadcastItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellIDBroadcastItem, options aper.DecodeState) (CellIDBroadcastItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellIDBroadcastItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellIDBroadcastItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellIDBroadcastItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDBroadcastItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellIDCancelledItemCodec binds the complete source value type.
func CellIDCancelledItemCodec() CellIDCancelledItemValueCodec {
	return CellIDCancelledItemValueCodec{path: "CellIDCancelledItem", decode: func(data []byte, options aper.DecodeState) (CellIDCancelledItem, error) {
		var value CellIDCancelledItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellIDCancelledItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellIDCancelledItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellIDCancelledItem, options aper.DecodeState) (CellIDCancelledItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellIDCancelledItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellIDCancelledItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellIDCancelledItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDCancelledItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CompletedCellinEAIItemCodec binds the complete source value type.
func CompletedCellinEAIItemCodec() CompletedCellinEAIItemValueCodec {
	return CompletedCellinEAIItemValueCodec{path: "CompletedCellinEAIItem", decode: func(data []byte, options aper.DecodeState) (CompletedCellinEAIItem, error) {
		var value CompletedCellinEAIItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CompletedCellinEAIItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CompletedCellinEAIItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CompletedCellinEAIItem, options aper.DecodeState) (CompletedCellinEAIItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCompletedCellinEAIItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CompletedCellinEAIItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCompletedCellinEAIItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CompletedCellinEAIItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CompletedCellinTAIItemCodec binds the complete source value type.
func CompletedCellinTAIItemCodec() CompletedCellinTAIItemValueCodec {
	return CompletedCellinTAIItemValueCodec{path: "CompletedCellinTAIItem", decode: func(data []byte, options aper.DecodeState) (CompletedCellinTAIItem, error) {
		var value CompletedCellinTAIItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CompletedCellinTAIItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CompletedCellinTAIItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CompletedCellinTAIItem, options aper.DecodeState) (CompletedCellinTAIItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCompletedCellinTAIItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CompletedCellinTAIItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCompletedCellinTAIItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CompletedCellinTAIItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ERABSetupItemCtxtSUResCodec binds the complete APER value type.
func ERABSetupItemCtxtSUResCodec() s19.ERABSetupItemCtxtSUResValueCodec {
	return ERABSetupItemCtxtSUResIEs().ERABSetupItemCtxtSURes().Codec()
}

// ERABToBeModifiedItemBearerModIndCodec binds the complete APER value type.
func ERABToBeModifiedItemBearerModIndCodec() ERABToBeModifiedItemBearerModIndValueCodec {
	return ERABToBeModifiedItemBearerModIndIEs().ERABToBeModifiedItemBearerModInd().Codec()
}

// ERABToBeSwitchedULItemCodec binds the complete APER value type.
func ERABToBeSwitchedULItemCodec() ERABToBeSwitchedULItemValueCodec {
	return ERABToBeSwitchedULItemIEs().ERABToBeSwitchedULItem().Codec()
}

// ERABUsageReportItemCodec binds the complete APER value type.
func ERABUsageReportItemCodec() ERABUsageReportItemValueCodec {
	return ERABUsageReportItemIEs().ERABUsageReportItem().Codec()
}
func BridgeAssistanceDataForCECapableUEsMethodMarshalAPERTo(v *AssistanceDataForCECapableUEs, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceDataForCECapableUEsMethodUnmarshalAPERFrom(v *AssistanceDataForCECapableUEs, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCancelledCellinEAIItemMethodMarshalAPERTo(v *CancelledCellinEAIItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCancelledCellinEAIItemMethodUnmarshalAPERFrom(v *CancelledCellinEAIItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCancelledCellinEAIValueCodecFieldCapture(v *CancelledCellinEAIValueCodec) *func(CancelledCellinEAI, aper.DecodeState) (CancelledCellinEAI, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinEAIValueCodecFieldCompare(v *CancelledCellinEAIValueCodec) *func(CancelledCellinEAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinEAIValueCodecFieldContext(v *CancelledCellinEAIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinEAIValueCodecFieldDecode(v *CancelledCellinEAIValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinEAI, error) {
	return &v.decode
}
func BridgeCancelledCellinEAIValueCodecFieldEncode(v *CancelledCellinEAIValueCodec) *func(CancelledCellinEAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinEAIValueCodecFieldPath(v *CancelledCellinEAIValueCodec) *aper.Path {
	return &v.path
}
func BridgeCancelledCellinTAIItemMethodMarshalAPERTo(v *CancelledCellinTAIItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCancelledCellinTAIItemMethodUnmarshalAPERFrom(v *CancelledCellinTAIItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCancelledCellinTAIValueCodecFieldCapture(v *CancelledCellinTAIValueCodec) *func(CancelledCellinTAI, aper.DecodeState) (CancelledCellinTAI, aper.Snapshot) {
	return &v.capture
}
func BridgeCancelledCellinTAIValueCodecFieldCompare(v *CancelledCellinTAIValueCodec) *func(CancelledCellinTAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCancelledCellinTAIValueCodecFieldContext(v *CancelledCellinTAIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCancelledCellinTAIValueCodecFieldDecode(v *CancelledCellinTAIValueCodec) *func([]byte, aper.DecodeState) (CancelledCellinTAI, error) {
	return &v.decode
}
func BridgeCancelledCellinTAIValueCodecFieldEncode(v *CancelledCellinTAIValueCodec) *func(CancelledCellinTAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCancelledCellinTAIValueCodecFieldPath(v *CancelledCellinTAIValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDBroadcastItemMethodMarshalAPERTo(v *CellIDBroadcastItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellIDBroadcastItemMethodUnmarshalAPERFrom(v *CellIDBroadcastItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIDBroadcastValueCodecFieldCapture(v *CellIDBroadcastValueCodec) *func(CellIDBroadcast, aper.DecodeState) (CellIDBroadcast, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDBroadcastValueCodecFieldCompare(v *CellIDBroadcastValueCodec) *func(CellIDBroadcast, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDBroadcastValueCodecFieldContext(v *CellIDBroadcastValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDBroadcastValueCodecFieldDecode(v *CellIDBroadcastValueCodec) *func([]byte, aper.DecodeState) (CellIDBroadcast, error) {
	return &v.decode
}
func BridgeCellIDBroadcastValueCodecFieldEncode(v *CellIDBroadcastValueCodec) *func(CellIDBroadcast, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDBroadcastValueCodecFieldPath(v *CellIDBroadcastValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIDCancelledItemMethodMarshalAPERTo(v *CellIDCancelledItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellIDCancelledItemMethodUnmarshalAPERFrom(v *CellIDCancelledItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIDCancelledValueCodecFieldCapture(v *CellIDCancelledValueCodec) *func(CellIDCancelled, aper.DecodeState) (CellIDCancelled, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIDCancelledValueCodecFieldCompare(v *CellIDCancelledValueCodec) *func(CellIDCancelled, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIDCancelledValueCodecFieldContext(v *CellIDCancelledValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIDCancelledValueCodecFieldDecode(v *CellIDCancelledValueCodec) *func([]byte, aper.DecodeState) (CellIDCancelled, error) {
	return &v.decode
}
func BridgeCellIDCancelledValueCodecFieldEncode(v *CellIDCancelledValueCodec) *func(CellIDCancelled, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIDCancelledValueCodecFieldPath(v *CellIDCancelledValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIdListforMDTValueCodecFieldCapture(v *CellIdListforMDTValueCodec) *func(CellIdListforMDT, aper.DecodeState) (CellIdListforMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIdListforMDTValueCodecFieldCompare(v *CellIdListforMDTValueCodec) *func(CellIdListforMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIdListforMDTValueCodecFieldContext(v *CellIdListforMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIdListforMDTValueCodecFieldDecode(v *CellIdListforMDTValueCodec) *func([]byte, aper.DecodeState) (CellIdListforMDT, error) {
	return &v.decode
}
func BridgeCellIdListforMDTValueCodecFieldEncode(v *CellIdListforMDTValueCodec) *func(CellIdListforMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIdListforMDTValueCodecFieldPath(v *CellIdListforMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIdListforQMCValueCodecFieldCapture(v *CellIdListforQMCValueCodec) *func(CellIdListforQMC, aper.DecodeState) (CellIdListforQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIdListforQMCValueCodecFieldCompare(v *CellIdListforQMCValueCodec) *func(CellIdListforQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIdListforQMCValueCodecFieldContext(v *CellIdListforQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIdListforQMCValueCodecFieldDecode(v *CellIdListforQMCValueCodec) *func([]byte, aper.DecodeState) (CellIdListforQMC, error) {
	return &v.decode
}
func BridgeCellIdListforQMCValueCodecFieldEncode(v *CellIdListforQMCValueCodec) *func(CellIdListforQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIdListforQMCValueCodecFieldPath(v *CellIdListforQMCValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellIdentifierAndCELevelForCECapableUEsFieldPerPadding(v *CellIdentifierAndCELevelForCECapableUEs) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceived(v *CellIdentifierAndCELevelForCECapableUEs) *bool {
	return &v.received
}
func BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedBytes(v *CellIdentifierAndCELevelForCECapableUEs) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellIdentifierAndCELevelForCECapableUEsFieldReceivedLocation(v *CellIdentifierAndCELevelForCECapableUEs) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellIdentifierAndCELevelForCECapableUEsMethodMarshalAPERBudget(v *CellIdentifierAndCELevelForCECapableUEs, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsMethodUnmarshalAPERFrom(v *CellIdentifierAndCELevelForCECapableUEs, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCapture(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *func(CellIdentifierAndCELevelForCECapableUEs, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot) {
	return &v.capture
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldCompare(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *func(CellIdentifierAndCELevelForCECapableUEs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldContext(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldDecode(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *func([]byte, aper.DecodeState) (CellIdentifierAndCELevelForCECapableUEs, error) {
	return &v.decode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldEncode(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *func(CellIdentifierAndCELevelForCECapableUEs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellIdentifierAndCELevelForCECapableUEsValueCodecFieldPath(v *CellIdentifierAndCELevelForCECapableUEsValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceENBUES1APIDIEBindingFieldCodec(v *CellTrafficTraceENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeCellTrafficTraceENBUES1APIDIEBindingFieldGet(v *CellTrafficTraceENBUES1APIDIEBinding) *func(*CellTrafficTraceIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeCellTrafficTraceENBUES1APIDIEBindingFieldInfo(v *CellTrafficTraceENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTraceENBUES1APIDIEBindingFieldInject(v *CellTrafficTraceENBUES1APIDIEBinding) *func(s00.ENBUES1APID) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCellTrafficTraceEUTRANCGIIEBindingFieldCodec(v *CellTrafficTraceEUTRANCGIIEBinding) *EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeCellTrafficTraceEUTRANCGIIEBindingFieldGet(v *CellTrafficTraceEUTRANCGIIEBinding) *func(*CellTrafficTraceIEValue) (*EUTRANCGI, bool) {
	return &v.get
}
func BridgeCellTrafficTraceEUTRANCGIIEBindingFieldInfo(v *CellTrafficTraceEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTraceEUTRANCGIIEBindingFieldInject(v *CellTrafficTraceEUTRANCGIIEBinding) *func(EUTRANCGI) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCellTrafficTraceEUTRANTraceIDIEBindingFieldCodec(v *CellTrafficTraceEUTRANTraceIDIEBinding) *s00.EUTRANTraceIDValueCodec {
	return &v.codec
}
func BridgeCellTrafficTraceEUTRANTraceIDIEBindingFieldGet(v *CellTrafficTraceEUTRANTraceIDIEBinding) *func(*CellTrafficTraceIEValue) (*s00.EUTRANTraceID, bool) {
	return &v.get
}
func BridgeCellTrafficTraceEUTRANTraceIDIEBindingFieldInfo(v *CellTrafficTraceEUTRANTraceIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTraceEUTRANTraceIDIEBindingFieldInject(v *CellTrafficTraceEUTRANTraceIDIEBinding) *func(s00.EUTRANTraceID) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldCapture(v *CellTrafficTraceIEContainerValueCodec) *func(CellTrafficTraceIEContainer, aper.DecodeState) (CellTrafficTraceIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldCompare(v *CellTrafficTraceIEContainerValueCodec) *func(CellTrafficTraceIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldContext(v *CellTrafficTraceIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(v *CellTrafficTraceIEContainerValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTraceIEContainer, error) {
	return &v.decode
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(v *CellTrafficTraceIEContainerValueCodec) *func(CellTrafficTraceIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceIEContainerValueCodecFieldPath(v *CellTrafficTraceIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceIEFieldFieldReplay(v *CellTrafficTraceIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeCellTrafficTraceIEFieldFieldWithoutReplay(v *CellTrafficTraceIEField) *bool {
	return &v.withoutReplay
}
func BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(v *CellTrafficTraceIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(v *CellTrafficTraceIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldCapture(v *CellTrafficTraceIEFieldValueCodec) *func(CellTrafficTraceIEField, aper.DecodeState) (CellTrafficTraceIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldCompare(v *CellTrafficTraceIEFieldValueCodec) *func(CellTrafficTraceIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldContext(v *CellTrafficTraceIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldDecode(v *CellTrafficTraceIEFieldValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTraceIEField, error) {
	return &v.decode
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldEncode(v *CellTrafficTraceIEFieldValueCodec) *func(CellTrafficTraceIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceIEFieldValueCodecFieldPath(v *CellTrafficTraceIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCapture(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *func(CellTrafficTraceIEValueERABIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCompare(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *func(CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldContext(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldDecode(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTraceIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldEncode(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *func(CellTrafficTraceIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldPath(v *CellTrafficTraceIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceIEValueFieldId(v *CellTrafficTraceIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeCellTrafficTraceIEValueFieldIsOpaque(v *CellTrafficTraceIEValue) *bool       { return &v.isOpaque }
func BridgeCellTrafficTraceIEValueFieldOpaque(v *CellTrafficTraceIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCellTrafficTraceIEValueFieldRowENBUES1APID(v *CellTrafficTraceIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeCellTrafficTraceIEValueFieldRowEUTRANCGI(v *CellTrafficTraceIEValue) **EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeCellTrafficTraceIEValueFieldRowEUTRANTraceID(v *CellTrafficTraceIEValue) **s00.EUTRANTraceID {
	return &v.rowEUTRANTraceID
}
func BridgeCellTrafficTraceIEValueFieldRowMMEUES1APID(v *CellTrafficTraceIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeCellTrafficTraceIEValueFieldRowPrivacyIndicator(v *CellTrafficTraceIEValue) **s00.PrivacyIndicator {
	return &v.rowPrivacyIndicator
}
func BridgeCellTrafficTraceIEValueFieldRowTraceCollectionEntityIPAddress(v *CellTrafficTraceIEValue) **s00.TransportLayerAddress {
	return &v.rowTraceCollectionEntityIPAddress
}
func BridgeCellTrafficTraceIEValueMethodCaptureSemantics(v CellTrafficTraceIEValue, a0 aper.SemanticCapture) CellTrafficTraceIEValue {
	return v.captureSemantics(a0)
}
func BridgeCellTrafficTraceIEValueMethodCompareSemantics(v CellTrafficTraceIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCellTrafficTraceIEValueMethodDecode(v CellTrafficTraceIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CellTrafficTraceIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeCellTrafficTraceIEValueMethodEncodeFresh(v CellTrafficTraceIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCellTrafficTraceIEValueMethodMatchesID(v CellTrafficTraceIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCellTrafficTraceIEValueMethodRule(v CellTrafficTraceIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTraceIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCapture(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolIEContainerList, aper.DecodeState) (CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCompare(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldContext(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldDecode(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTraceIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldEncode(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *func(CellTrafficTraceIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldPath(v *CellTrafficTraceIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTrafficTraceMMEUES1APIDIEBindingFieldCodec(v *CellTrafficTraceMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeCellTrafficTraceMMEUES1APIDIEBindingFieldGet(v *CellTrafficTraceMMEUES1APIDIEBinding) *func(*CellTrafficTraceIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeCellTrafficTraceMMEUES1APIDIEBindingFieldInfo(v *CellTrafficTraceMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTraceMMEUES1APIDIEBindingFieldInject(v *CellTrafficTraceMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCellTrafficTracePrivacyIndicatorIEBindingFieldCodec(v *CellTrafficTracePrivacyIndicatorIEBinding) *s01.PrivacyIndicatorValueCodec {
	return &v.codec
}
func BridgeCellTrafficTracePrivacyIndicatorIEBindingFieldGet(v *CellTrafficTracePrivacyIndicatorIEBinding) *func(*CellTrafficTraceIEValue) (*s00.PrivacyIndicator, bool) {
	return &v.get
}
func BridgeCellTrafficTracePrivacyIndicatorIEBindingFieldInfo(v *CellTrafficTracePrivacyIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTracePrivacyIndicatorIEBindingFieldInject(v *CellTrafficTracePrivacyIndicatorIEBinding) *func(s00.PrivacyIndicator) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCellTrafficTraceTransportLayerAddressIEBindingFieldCodec(v *CellTrafficTraceTransportLayerAddressIEBinding) *s02.TransportLayerAddressValueCodec {
	return &v.codec
}
func BridgeCellTrafficTraceTransportLayerAddressIEBindingFieldGet(v *CellTrafficTraceTransportLayerAddressIEBinding) *func(*CellTrafficTraceIEValue) (*s00.TransportLayerAddress, bool) {
	return &v.get
}
func BridgeCellTrafficTraceTransportLayerAddressIEBindingFieldInfo(v *CellTrafficTraceTransportLayerAddressIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeCellTrafficTraceTransportLayerAddressIEBindingFieldInject(v *CellTrafficTraceTransportLayerAddressIEBinding) *func(s00.TransportLayerAddress) CellTrafficTraceIEValue {
	return &v.inject
}
func BridgeCompletedCellinEAIItemMethodMarshalAPERTo(v *CompletedCellinEAIItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCompletedCellinEAIItemMethodUnmarshalAPERFrom(v *CompletedCellinEAIItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCompletedCellinEAIValueCodecFieldCapture(v *CompletedCellinEAIValueCodec) *func(CompletedCellinEAI, aper.DecodeState) (CompletedCellinEAI, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinEAIValueCodecFieldCompare(v *CompletedCellinEAIValueCodec) *func(CompletedCellinEAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinEAIValueCodecFieldContext(v *CompletedCellinEAIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinEAIValueCodecFieldDecode(v *CompletedCellinEAIValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinEAI, error) {
	return &v.decode
}
func BridgeCompletedCellinEAIValueCodecFieldEncode(v *CompletedCellinEAIValueCodec) *func(CompletedCellinEAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinEAIValueCodecFieldPath(v *CompletedCellinEAIValueCodec) *aper.Path {
	return &v.path
}
func BridgeCompletedCellinTAIItemMethodMarshalAPERTo(v *CompletedCellinTAIItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCompletedCellinTAIItemMethodUnmarshalAPERFrom(v *CompletedCellinTAIItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCompletedCellinTAIValueCodecFieldCapture(v *CompletedCellinTAIValueCodec) *func(CompletedCellinTAI, aper.DecodeState) (CompletedCellinTAI, aper.Snapshot) {
	return &v.capture
}
func BridgeCompletedCellinTAIValueCodecFieldCompare(v *CompletedCellinTAIValueCodec) *func(CompletedCellinTAI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCompletedCellinTAIValueCodecFieldContext(v *CompletedCellinTAIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCompletedCellinTAIValueCodecFieldDecode(v *CompletedCellinTAIValueCodec) *func([]byte, aper.DecodeState) (CompletedCellinTAI, error) {
	return &v.decode
}
func BridgeCompletedCellinTAIValueCodecFieldEncode(v *CompletedCellinTAIValueCodec) *func(CompletedCellinTAI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCompletedCellinTAIValueCodecFieldPath(v *CompletedCellinTAIValueCodec) *aper.Path {
	return &v.path
}
func BridgeECGIListForRestartValueCodecFieldCapture(v *ECGIListForRestartValueCodec) *func(ECGIListForRestart, aper.DecodeState) (ECGIListForRestart, aper.Snapshot) {
	return &v.capture
}
func BridgeECGIListForRestartValueCodecFieldCompare(v *ECGIListForRestartValueCodec) *func(ECGIListForRestart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeECGIListForRestartValueCodecFieldContext(v *ECGIListForRestartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECGIListForRestartValueCodecFieldDecode(v *ECGIListForRestartValueCodec) *func([]byte, aper.DecodeState) (ECGIListForRestart, error) {
	return &v.decode
}
func BridgeECGIListForRestartValueCodecFieldEncode(v *ECGIListForRestartValueCodec) *func(ECGIListForRestart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECGIListForRestartValueCodecFieldPath(v *ECGIListForRestartValueCodec) *aper.Path {
	return &v.path
}
func BridgeECGIListValueCodecFieldCapture(v *ECGIListValueCodec) *func(ECGIList, aper.DecodeState) (ECGIList, aper.Snapshot) {
	return &v.capture
}
func BridgeECGIListValueCodecFieldCompare(v *ECGIListValueCodec) *func(ECGIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeECGIListValueCodecFieldContext(v *ECGIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECGIListValueCodecFieldDecode(v *ECGIListValueCodec) *func([]byte, aper.DecodeState) (ECGIList, error) {
	return &v.decode
}
func BridgeECGIListValueCodecFieldEncode(v *ECGIListValueCodec) *func(ECGIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECGIListValueCodecFieldPath(v *ECGIListValueCodec) *aper.Path { return &v.path }
func BridgeERABSetupListBearerSUResValueCodecFieldCapture(v *ERABSetupListBearerSUResValueCodec) *func(ERABSetupListBearerSURes, aper.DecodeState) (ERABSetupListBearerSURes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupListBearerSUResValueCodecFieldCompare(v *ERABSetupListBearerSUResValueCodec) *func(ERABSetupListBearerSURes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupListBearerSUResValueCodecFieldContext(v *ERABSetupListBearerSUResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupListBearerSUResValueCodecFieldDecode(v *ERABSetupListBearerSUResValueCodec) *func([]byte, aper.DecodeState) (ERABSetupListBearerSURes, error) {
	return &v.decode
}
func BridgeERABSetupListBearerSUResValueCodecFieldEncode(v *ERABSetupListBearerSUResValueCodec) *func(ERABSetupListBearerSURes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupListBearerSUResValueCodecFieldPath(v *ERABSetupListBearerSUResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupListCtxtSUResValueCodecFieldCapture(v *ERABSetupListCtxtSUResValueCodec) *func(ERABSetupListCtxtSURes, aper.DecodeState) (ERABSetupListCtxtSURes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupListCtxtSUResValueCodecFieldCompare(v *ERABSetupListCtxtSUResValueCodec) *func(ERABSetupListCtxtSURes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupListCtxtSUResValueCodecFieldContext(v *ERABSetupListCtxtSUResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupListCtxtSUResValueCodecFieldDecode(v *ERABSetupListCtxtSUResValueCodec) *func([]byte, aper.DecodeState) (ERABSetupListCtxtSURes, error) {
	return &v.decode
}
func BridgeERABSetupListCtxtSUResValueCodecFieldEncode(v *ERABSetupListCtxtSUResValueCodec) *func(ERABSetupListCtxtSURes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupListCtxtSUResValueCodecFieldPath(v *ERABSetupListCtxtSUResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldCapture(v *ERABSubjecttoDataForwardingListValueCodec) *func(ERABSubjecttoDataForwardingList, aper.DecodeState) (ERABSubjecttoDataForwardingList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldCompare(v *ERABSubjecttoDataForwardingListValueCodec) *func(ERABSubjecttoDataForwardingList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldContext(v *ERABSubjecttoDataForwardingListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldDecode(v *ERABSubjecttoDataForwardingListValueCodec) *func([]byte, aper.DecodeState) (ERABSubjecttoDataForwardingList, error) {
	return &v.decode
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldEncode(v *ERABSubjecttoDataForwardingListValueCodec) *func(ERABSubjecttoDataForwardingList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSubjecttoDataForwardingListValueCodecFieldPath(v *ERABSubjecttoDataForwardingListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndIEContainer, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABToBeModifiedItemBearerModIndIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndIEContainerValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldFieldReplay(v *ERABToBeModifiedItemBearerModIndIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v *ERABToBeModifiedItemBearerModIndIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(v *ERABToBeModifiedItemBearerModIndIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(v *ERABToBeModifiedItemBearerModIndIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndIEField, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEField, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABToBeModifiedItemBearerModIndIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndIEFieldValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndIEValueFieldId(v *ERABToBeModifiedItemBearerModIndIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeModifiedItemBearerModIndIEValueFieldIsOpaque(v *ERABToBeModifiedItemBearerModIndIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeModifiedItemBearerModIndIEValueFieldOpaque(v *ERABToBeModifiedItemBearerModIndIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeModifiedItemBearerModIndIEValueFieldRowERABToBeModifiedItemBearerModInd(v *ERABToBeModifiedItemBearerModIndIEValue) **ERABToBeModifiedItemBearerModInd {
	return &v.rowERABToBeModifiedItemBearerModInd
}
func BridgeERABToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v ERABToBeModifiedItemBearerModIndIEValue, a0 aper.SemanticCapture) ERABToBeModifiedItemBearerModIndIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v ERABToBeModifiedItemBearerModIndIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueMethodMatchesID(v ERABToBeModifiedItemBearerModIndIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeModifiedItemBearerModIndIEValueMethodRule(v ERABToBeModifiedItemBearerModIndIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldCapture(v *ERABToBeModifiedListBearerModIndValueCodec) *func(ERABToBeModifiedListBearerModInd, aper.DecodeState) (ERABToBeModifiedListBearerModInd, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldCompare(v *ERABToBeModifiedListBearerModIndValueCodec) *func(ERABToBeModifiedListBearerModInd, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldContext(v *ERABToBeModifiedListBearerModIndValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldDecode(v *ERABToBeModifiedListBearerModIndValueCodec) *func([]byte, aper.DecodeState) (ERABToBeModifiedListBearerModInd, error) {
	return &v.decode
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldEncode(v *ERABToBeModifiedListBearerModIndValueCodec) *func(ERABToBeModifiedListBearerModInd, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeModifiedListBearerModIndValueCodecFieldPath(v *ERABToBeModifiedListBearerModIndValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCapture(v *ERABToBeSwitchedULItemIEContainerValueCodec) *func(ERABToBeSwitchedULItemIEContainer, aper.DecodeState) (ERABToBeSwitchedULItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldCompare(v *ERABToBeSwitchedULItemIEContainerValueCodec) *func(ERABToBeSwitchedULItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldContext(v *ERABToBeSwitchedULItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldDecode(v *ERABToBeSwitchedULItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEContainer, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldEncode(v *ERABToBeSwitchedULItemIEContainerValueCodec) *func(ERABToBeSwitchedULItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemIEContainerValueCodecFieldPath(v *ERABToBeSwitchedULItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemIEFieldFieldReplay(v *ERABToBeSwitchedULItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABToBeSwitchedULItemIEFieldFieldWithoutReplay(v *ERABToBeSwitchedULItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABToBeSwitchedULItemIEFieldMethodMarshalAPERTo(v *ERABToBeSwitchedULItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABToBeSwitchedULItemIEFieldMethodUnmarshalAPERFrom(v *ERABToBeSwitchedULItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCapture(v *ERABToBeSwitchedULItemIEFieldValueCodec) *func(ERABToBeSwitchedULItemIEField, aper.DecodeState) (ERABToBeSwitchedULItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldCompare(v *ERABToBeSwitchedULItemIEFieldValueCodec) *func(ERABToBeSwitchedULItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldContext(v *ERABToBeSwitchedULItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldDecode(v *ERABToBeSwitchedULItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEField, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldEncode(v *ERABToBeSwitchedULItemIEFieldValueCodec) *func(ERABToBeSwitchedULItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemIEFieldValueCodecFieldPath(v *ERABToBeSwitchedULItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedULItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemIEValueFieldId(v *ERABToBeSwitchedULItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABToBeSwitchedULItemIEValueFieldIsOpaque(v *ERABToBeSwitchedULItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABToBeSwitchedULItemIEValueFieldOpaque(v *ERABToBeSwitchedULItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABToBeSwitchedULItemIEValueFieldRowERABToBeSwitchedULItem(v *ERABToBeSwitchedULItemIEValue) **ERABToBeSwitchedULItem {
	return &v.rowERABToBeSwitchedULItem
}
func BridgeERABToBeSwitchedULItemIEValueMethodCaptureSemantics(v ERABToBeSwitchedULItemIEValue, a0 aper.SemanticCapture) ERABToBeSwitchedULItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABToBeSwitchedULItemIEValueMethodCompareSemantics(v ERABToBeSwitchedULItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABToBeSwitchedULItemIEValueMethodMatchesID(v ERABToBeSwitchedULItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABToBeSwitchedULItemIEValueMethodRule(v ERABToBeSwitchedULItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedULItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *func(ERABToBeSwitchedULItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABToBeSwitchedULItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABToBeSwitchedULListValueCodecFieldCapture(v *ERABToBeSwitchedULListValueCodec) *func(ERABToBeSwitchedULList, aper.DecodeState) (ERABToBeSwitchedULList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABToBeSwitchedULListValueCodecFieldCompare(v *ERABToBeSwitchedULListValueCodec) *func(ERABToBeSwitchedULList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABToBeSwitchedULListValueCodecFieldContext(v *ERABToBeSwitchedULListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABToBeSwitchedULListValueCodecFieldDecode(v *ERABToBeSwitchedULListValueCodec) *func([]byte, aper.DecodeState) (ERABToBeSwitchedULList, error) {
	return &v.decode
}
func BridgeERABToBeSwitchedULListValueCodecFieldEncode(v *ERABToBeSwitchedULListValueCodec) *func(ERABToBeSwitchedULList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABToBeSwitchedULListValueCodecFieldPath(v *ERABToBeSwitchedULListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldCapture(v *ERABUsageReportItemIEContainerValueCodec) *func(ERABUsageReportItemIEContainer, aper.DecodeState) (ERABUsageReportItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldCompare(v *ERABUsageReportItemIEContainerValueCodec) *func(ERABUsageReportItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldContext(v *ERABUsageReportItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldDecode(v *ERABUsageReportItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemIEContainer, error) {
	return &v.decode
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldEncode(v *ERABUsageReportItemIEContainerValueCodec) *func(ERABUsageReportItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemIEContainerValueCodecFieldPath(v *ERABUsageReportItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemIEFieldFieldReplay(v *ERABUsageReportItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABUsageReportItemIEFieldFieldWithoutReplay(v *ERABUsageReportItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABUsageReportItemIEFieldMethodMarshalAPERTo(v *ERABUsageReportItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABUsageReportItemIEFieldMethodUnmarshalAPERFrom(v *ERABUsageReportItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldCapture(v *ERABUsageReportItemIEFieldValueCodec) *func(ERABUsageReportItemIEField, aper.DecodeState) (ERABUsageReportItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldCompare(v *ERABUsageReportItemIEFieldValueCodec) *func(ERABUsageReportItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldContext(v *ERABUsageReportItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldDecode(v *ERABUsageReportItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemIEField, error) {
	return &v.decode
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldEncode(v *ERABUsageReportItemIEFieldValueCodec) *func(ERABUsageReportItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemIEFieldValueCodecFieldPath(v *ERABUsageReportItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *func(ERABUsageReportItemIEValueERABIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *func(ERABUsageReportItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *func(ERABUsageReportItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABUsageReportItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemIEValueFieldId(v *ERABUsageReportItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABUsageReportItemIEValueFieldIsOpaque(v *ERABUsageReportItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABUsageReportItemIEValueFieldOpaque(v *ERABUsageReportItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABUsageReportItemIEValueFieldRowERABUsageReportItem(v *ERABUsageReportItemIEValue) **ERABUsageReportItem {
	return &v.rowERABUsageReportItem
}
func BridgeERABUsageReportItemIEValueMethodCaptureSemantics(v ERABUsageReportItemIEValue, a0 aper.SemanticCapture) ERABUsageReportItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABUsageReportItemIEValueMethodCompareSemantics(v ERABUsageReportItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABUsageReportItemIEValueMethodMatchesID(v ERABUsageReportItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABUsageReportItemIEValueMethodRule(v ERABUsageReportItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABUsageReportItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *func(ERABUsageReportItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABUsageReportItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABUsageReportListValueCodecFieldCapture(v *ERABUsageReportListValueCodec) *func(ERABUsageReportList, aper.DecodeState) (ERABUsageReportList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABUsageReportListValueCodecFieldCompare(v *ERABUsageReportListValueCodec) *func(ERABUsageReportList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABUsageReportListValueCodecFieldContext(v *ERABUsageReportListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABUsageReportListValueCodecFieldDecode(v *ERABUsageReportListValueCodec) *func([]byte, aper.DecodeState) (ERABUsageReportList, error) {
	return &v.decode
}
func BridgeERABUsageReportListValueCodecFieldEncode(v *ERABUsageReportListValueCodec) *func(ERABUsageReportList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABUsageReportListValueCodecFieldPath(v *ERABUsageReportListValueCodec) *aper.Path {
	return &v.path
}
func BridgeEUTRANCGIFieldPerPadding(v *EUTRANCGI) *aper.FinalPadding   { return &v.perPadding }
func BridgeEUTRANCGIFieldReceived(v *EUTRANCGI) *bool                  { return &v.received }
func BridgeEUTRANCGIFieldReceivedBytes(v *EUTRANCGI) *aper.WireSpan    { return &v.receivedBytes }
func BridgeEUTRANCGIFieldReceivedLocation(v *EUTRANCGI) *aper.Location { return &v.receivedLocation }
func BridgeEUTRANCGIMethodMarshalAPERBudget(v *EUTRANCGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEUTRANCGIMethodMarshalAPERTo(v *EUTRANCGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEUTRANCGIMethodUnmarshalAPERFrom(v *EUTRANCGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEUTRANCGIValueCodecFieldCapture(v *EUTRANCGIValueCodec) *func(EUTRANCGI, aper.DecodeState) (EUTRANCGI, aper.Snapshot) {
	return &v.capture
}
func BridgeEUTRANCGIValueCodecFieldCompare(v *EUTRANCGIValueCodec) *func(EUTRANCGI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEUTRANCGIValueCodecFieldContext(v *EUTRANCGIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANCGIValueCodecFieldDecode(v *EUTRANCGIValueCodec) *func([]byte, aper.DecodeState) (EUTRANCGI, error) {
	return &v.decode
}
func BridgeEUTRANCGIValueCodecFieldEncode(v *EUTRANCGIValueCodec) *func(EUTRANCGI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANCGIValueCodecFieldPath(v *EUTRANCGIValueCodec) *aper.Path { return &v.path }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *CellTrafficTraceIEValue) Selected() (any, bool) {
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
	case 86:
		if value, ok := v.AsEUTRANTraceID(); ok {
			return value, true
		}
	case 100:
		if value, ok := v.AsEUTRANCGI(); ok {
			return value, true
		}
	case 131:
		if value, ok := v.AsTraceCollectionEntityIPAddress(); ok {
			return value, true
		}
	case 166:
		if value, ok := v.AsPrivacyIndicator(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeModifiedItemBearerModIndIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 200:
		if value, ok := v.AsERABToBeModifiedItemBearerModInd(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABToBeSwitchedULItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 94:
		if value, ok := v.AsERABToBeSwitchedULItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABUsageReportItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 267:
		if value, ok := v.AsERABUsageReportItem(); ok {
			return value, true
		}
	}
	return nil, false
}
