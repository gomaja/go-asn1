// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s17 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s17

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: a single information element field.
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer = BearersSubjectToEarlyStatusTransferItemIEField

// BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: a single information element field.
type BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer = BearersSubjectToDLDiscardingItemIEField

// DAPSResponseInfoListIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{DAPSResponseInfoListIEs}} of TS 36.413: a single information element field.
type DAPSResponseInfoListIEValueProtocolIESingleContainer = DAPSResponseInfoListIEField

// BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding binds BearersSubjectToDLDiscardingItem to the Bearers-SubjectToDLDiscarding-ItemIEs object set of TS 36.413.
type BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding struct {
	info   s00.FieldInfo
	codec  BearersSubjectToDLDiscardingItemValueCodec
	inject func(BearersSubjectToDLDiscardingItem,

	) BearersSubjectToDLDiscardingItemIEValue

	get func(*BearersSubjectToDLDiscardingItemIEValue,

	) (*BearersSubjectToDLDiscardingItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) Codec() BearersSubjectToDLDiscardingItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) New(value BearersSubjectToDLDiscardingItem,

) (BearersSubjectToDLDiscardingItemIEField, error) {
	if b.inject == nil {
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) Get(field *BearersSubjectToDLDiscardingItemIEField) (*BearersSubjectToDLDiscardingItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToDLDiscardingItemValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItem].
type BearersSubjectToDLDiscardingItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItem,

		error)
	encode func(BearersSubjectToDLDiscardingItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItem, aper.DecodeState,

	) (BearersSubjectToDLDiscardingItem, aper.Snapshot,

	)
	compare func(BearersSubjectToDLDiscardingItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemValueCodec) New(value BearersSubjectToDLDiscardingItem,

) (BearersSubjectToDLDiscardingItemAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEField is ProtocolIE-Field {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: an information element field.
type BearersSubjectToDLDiscardingItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToDLDiscardingItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEField) WithoutReplay() BearersSubjectToDLDiscardingItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToDLDiscardingItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToDLDiscardingItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToDLDiscardingItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToDLDiscardingItemIEField{}
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
	var zero BearersSubjectToDLDiscardingItemIEValue

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

// BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding binds BearersSubjectToEarlyStatusTransferItem to the Bearers-SubjectToEarlyStatusTransfer-ItemIEs object set of TS 36.413.
type BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding struct {
	info   s00.FieldInfo
	codec  BearersSubjectToEarlyStatusTransferItemValueCodec
	inject func(BearersSubjectToEarlyStatusTransferItem,

	) BearersSubjectToEarlyStatusTransferItemIEValue

	get func(*BearersSubjectToEarlyStatusTransferItemIEValue,

	) (*BearersSubjectToEarlyStatusTransferItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) Codec() BearersSubjectToEarlyStatusTransferItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) New(value BearersSubjectToEarlyStatusTransferItem,

) (BearersSubjectToEarlyStatusTransferItemIEField, error) {
	if b.inject == nil {
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) Get(field *BearersSubjectToEarlyStatusTransferItemIEField) (*BearersSubjectToEarlyStatusTransferItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToEarlyStatusTransferItemValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItem].
type BearersSubjectToEarlyStatusTransferItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItem,

		error)
	encode func(BearersSubjectToEarlyStatusTransferItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItem, aper.DecodeState,

	) (BearersSubjectToEarlyStatusTransferItem, aper.Snapshot,

	)
	compare func(BearersSubjectToEarlyStatusTransferItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) New(value BearersSubjectToEarlyStatusTransferItem,

) (BearersSubjectToEarlyStatusTransferItemAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEField is ProtocolIE-Field {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: an information element field.
type BearersSubjectToEarlyStatusTransferItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToEarlyStatusTransferItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEField) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToEarlyStatusTransferItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToEarlyStatusTransferItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToEarlyStatusTransferItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToEarlyStatusTransferItemIEField{}
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
	var zero BearersSubjectToEarlyStatusTransferItemIEValue

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

// BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding binds COUNTvaluePDCPSNlength18 to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding struct {
	info   s00.ExtensionInfo
	codec  COUNTvaluePDCPSNlength18ValueCodec
	inject func(s16.COUNTvaluePDCPSNlength18,

	) s16.BearersSubjectToStatusTransferItemExtIEsValue

	get func(*s16.BearersSubjectToStatusTransferItemExtIEsValue,

	) (*s16.COUNTvaluePDCPSNlength18,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Codec() COUNTvaluePDCPSNlength18ValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) New(value s16.COUNTvaluePDCPSNlength18,

) (s16.BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return s16.BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding) Get(field *s16.BearersSubjectToStatusTransferItemExtIEsExtField) (*s16.COUNTvaluePDCPSNlength18,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// COUNTvaluePDCPSNlength18ValueCodec is the concrete ValueCodec[COUNTvaluePDCPSNlength18].
type COUNTvaluePDCPSNlength18ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s16.COUNTvaluePDCPSNlength18,

		error)
	encode func(s16.COUNTvaluePDCPSNlength18,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s16.COUNTvaluePDCPSNlength18, aper.DecodeState,

	) (s16.COUNTvaluePDCPSNlength18, aper.Snapshot,

	)
	compare func(s16.COUNTvaluePDCPSNlength18, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvaluePDCPSNlength18ValueCodec) New(value s16.COUNTvaluePDCPSNlength18,

) (COUNTvaluePDCPSNlength18APERValue, error) {
	if c.encode == nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return COUNTvaluePDCPSNlength18APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvaluePDCPSNlength18ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (COUNTvaluePDCPSNlength18APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return COUNTvaluePDCPSNlength18APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return COUNTvaluePDCPSNlength18APERValue{}, report, aper.OperationError(err, c.path)
		}
		return COUNTvaluePDCPSNlength18APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return COUNTvaluePDCPSNlength18APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvaluePDCPSNlength18ValueCodec) EncodeAPER(value COUNTvaluePDCPSNlength18APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c COUNTvaluePDCPSNlength18ValueCodec) encodeBudgetValue(value s16.COUNTvaluePDCPSNlength18,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvaluePDCPSNlength18ValueCodec) encodeChanged(value s16.COUNTvaluePDCPSNlength18,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding binds ReceiveStatusOfULPDCPSDUsPDCPSNlength18 to the Bearers-SubjectToStatusTransfer-ItemExtIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec
	inject func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	) s16.BearersSubjectToStatusTransferItemExtIEsValue

	get func(*s16.BearersSubjectToStatusTransferItemExtIEsValue,

	) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Codec() s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) New(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

) (s16.BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if b.inject == nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return s16.BearersSubjectToStatusTransferItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding) Get(field *s16.BearersSubjectToStatusTransferItemExtIEsExtField) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// DAPSResponseInfoListDAPSResponseInfoItemIEBinding binds DAPSResponseInfoItem to the DAPSResponseInfoListIEs object set of TS 36.413.
type DAPSResponseInfoListDAPSResponseInfoItemIEBinding struct {
	info   s00.FieldInfo
	codec  DAPSResponseInfoItemValueCodec
	inject func(DAPSResponseInfoItem,

	) DAPSResponseInfoListIEValue

	get func(*DAPSResponseInfoListIEValue,

	) (*DAPSResponseInfoItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Codec() DAPSResponseInfoItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) New(value DAPSResponseInfoItem,

) (DAPSResponseInfoListIEField, error) {
	if b.inject == nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Value.New")
	}
	return DAPSResponseInfoListIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DAPSResponseInfoListDAPSResponseInfoItemIEBinding) Get(field *DAPSResponseInfoListIEField) (*DAPSResponseInfoItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DAPSResponseInfoItemValueCodec is the concrete ValueCodec[DAPSResponseInfoItem].
type DAPSResponseInfoItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoItem,

		error)
	encode func(DAPSResponseInfoItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoItem, aper.DecodeState,

	) (DAPSResponseInfoItem, aper.Snapshot,

	)
	compare func(DAPSResponseInfoItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoItemValueCodec) New(value DAPSResponseInfoItem,

) (DAPSResponseInfoItemAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoItemValueCodec) EncodeAPER(value DAPSResponseInfoItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoItemValueCodec) encodeBudgetValue(value DAPSResponseInfoItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoItemValueCodec) encodeChanged(value DAPSResponseInfoItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEField is ProtocolIE-Field {{DAPSResponseInfoListIEs}} of TS 36.413: an information element field.
type DAPSResponseInfoListIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DAPSResponseInfoListIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEField) WithoutReplay() DAPSResponseInfoListIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DAPSResponseInfoListIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DAPSResponseInfoListIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *DAPSResponseInfoListIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoListIEField{}
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
	var zero DAPSResponseInfoListIEValue

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

// DAPSRequestInfoValueCodec is the concrete ValueCodec[DAPSRequestInfo].
type DAPSRequestInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSRequestInfo,

		error)
	encode func(DAPSRequestInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSRequestInfo, aper.DecodeState,

	) (DAPSRequestInfo, aper.Snapshot,

	)
	compare func(DAPSRequestInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSRequestInfoValueCodec) New(value DAPSRequestInfo,

) (DAPSRequestInfoAPERValue, error) {
	if c.encode == nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSRequestInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSRequestInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSRequestInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSRequestInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSRequestInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSRequestInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSRequestInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSRequestInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSRequestInfoValueCodec) EncodeAPER(value DAPSRequestInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSRequestInfoValueCodec) encodeBudgetValue(value DAPSRequestInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSRequestInfoValueCodec) encodeChanged(value DAPSRequestInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingListValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingList].
type BearersSubjectToDLDiscardingListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingList,

		error)
	encode func(BearersSubjectToDLDiscardingList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingList, aper.DecodeState,

	) (BearersSubjectToDLDiscardingList, aper.Snapshot,

	)
	compare func(BearersSubjectToDLDiscardingList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingListValueCodec) New(value BearersSubjectToDLDiscardingList,

) (BearersSubjectToDLDiscardingListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingListValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingListValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingListValueCodec) encodeChanged(value BearersSubjectToDLDiscardingList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CauseValueCodec is the concrete ValueCodec[Cause].
type CauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cause,

		error)
	encode func(Cause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cause, aper.DecodeState,

	) (Cause, aper.Snapshot,

	)
	compare func(Cause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CauseValueCodec) New(value Cause,

) (CauseAPERValue, error) {
	if c.encode == nil {
		return CauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CauseValueCodec) EncodeAPER(value CauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CauseValueCodec) encodeBudgetValue(value Cause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CauseValueCodec) encodeChanged(value Cause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListValueCodec is the concrete ValueCodec[DAPSResponseInfoList].
type DAPSResponseInfoListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoList,

		error)
	encode func(DAPSResponseInfoList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoList, aper.DecodeState,

	) (DAPSResponseInfoList, aper.Snapshot,

	)
	compare func(DAPSResponseInfoList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListValueCodec) New(value DAPSResponseInfoList,

) (DAPSResponseInfoListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListValueCodec) EncodeAPER(value DAPSResponseInfoListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListValueCodec) encodeBudgetValue(value DAPSResponseInfoList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListValueCodec) encodeChanged(value DAPSResponseInfoList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DLCPSecurityInformationValueCodec is the concrete ValueCodec[DLCPSecurityInformation].
type DLCPSecurityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DLCPSecurityInformation,

		error)
	encode func(DLCPSecurityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DLCPSecurityInformation, aper.DecodeState,

	) (DLCPSecurityInformation, aper.Snapshot,

	)
	compare func(DLCPSecurityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLCPSecurityInformationValueCodec) New(value DLCPSecurityInformation,

) (DLCPSecurityInformationAPERValue, error) {
	if c.encode == nil {
		return DLCPSecurityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DLCPSecurityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLCPSecurityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DLCPSecurityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DLCPSecurityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DLCPSecurityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DLCPSecurityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DLCPSecurityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DLCPSecurityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DLCPSecurityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DLCPSecurityInformationValueCodec) EncodeAPER(value DLCPSecurityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DLCPSecurityInformationValueCodec) encodeBudgetValue(value DLCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLCPSecurityInformationValueCodec) encodeChanged(value DLCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGMembershipInfoValueCodec is the concrete ValueCodec[CSGMembershipInfo].
type CSGMembershipInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGMembershipInfo,

		error)
	encode func(CSGMembershipInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGMembershipInfo, aper.DecodeState,

	) (CSGMembershipInfo, aper.Snapshot,

	)
	compare func(CSGMembershipInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGMembershipInfoValueCodec) New(value CSGMembershipInfo,

) (CSGMembershipInfoAPERValue, error) {
	if c.encode == nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGMembershipInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGMembershipInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGMembershipInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGMembershipInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGMembershipInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGMembershipInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGMembershipInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGMembershipInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGMembershipInfoValueCodec) EncodeAPER(value CSGMembershipInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGMembershipInfoValueCodec) encodeBudgetValue(value CSGMembershipInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGMembershipInfoValueCodec) encodeChanged(value CSGMembershipInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListValueCodec is the concrete ValueCodec[CSGIdList].
type CSGIdListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdList,

		error)
	encode func(CSGIdList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdList, aper.DecodeState,

	) (CSGIdList, aper.Snapshot,

	)
	compare func(CSGIdList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListValueCodec) New(value CSGIdList,

) (CSGIdListAPERValue, error) {
	if c.encode == nil {
		return CSGIdListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListValueCodec) EncodeAPER(value CSGIdListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGIdListValueCodec) encodeBudgetValue(value CSGIdList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListValueCodec) encodeChanged(value CSGIdList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// Cdma2000OneXSRVCCInfoValueCodec is the concrete ValueCodec[Cdma2000OneXSRVCCInfo].
type Cdma2000OneXSRVCCInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfo,

		error)
	encode func(Cdma2000OneXSRVCCInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Cdma2000OneXSRVCCInfo, aper.DecodeState,

	) (Cdma2000OneXSRVCCInfo, aper.Snapshot,

	)
	compare func(Cdma2000OneXSRVCCInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c Cdma2000OneXSRVCCInfoValueCodec) New(value Cdma2000OneXSRVCCInfo,

) (Cdma2000OneXSRVCCInfoAPERValue, error) {
	if c.encode == nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return Cdma2000OneXSRVCCInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c Cdma2000OneXSRVCCInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (Cdma2000OneXSRVCCInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return Cdma2000OneXSRVCCInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return Cdma2000OneXSRVCCInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return Cdma2000OneXSRVCCInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return Cdma2000OneXSRVCCInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c Cdma2000OneXSRVCCInfoValueCodec) EncodeAPER(value Cdma2000OneXSRVCCInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c Cdma2000OneXSRVCCInfoValueCodec) encodeBudgetValue(value Cdma2000OneXSRVCCInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c Cdma2000OneXSRVCCInfoValueCodec) encodeChanged(value Cdma2000OneXSRVCCInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferListValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferList].
type BearersSubjectToEarlyStatusTransferListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferList,

		error)
	encode func(BearersSubjectToEarlyStatusTransferList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferList, aper.DecodeState,

	) (BearersSubjectToEarlyStatusTransferList, aper.Snapshot,

	)
	compare func(BearersSubjectToEarlyStatusTransferList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferListValueCodec) New(value BearersSubjectToEarlyStatusTransferList,

) (BearersSubjectToEarlyStatusTransferListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferListValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferListValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferListValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// COUNTvalueValueCodec is the concrete ValueCodec[COUNTvalue].
type COUNTvalueValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s16.COUNTvalue,

		error)
	encode func(s16.COUNTvalue,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s16.COUNTvalue, aper.DecodeState,

	) (s16.COUNTvalue, aper.Snapshot,

	)
	compare func(s16.COUNTvalue, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c COUNTvalueValueCodec) New(value s16.COUNTvalue,

) (s16.COUNTvalueAPERValue, error) {
	if c.encode == nil {
		return s16.COUNTvalueAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s16.COUNTvalueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s16.COUNTvalueAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s16.COUNTvalueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c COUNTvalueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s16.COUNTvalueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s16.COUNTvalueAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s16.COUNTvalueAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s16.COUNTvalueAPERValue {
			sealed := s16.COUNTvalueAPERValue{Value: value}
			*s16.BridgeCOUNTvalueAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s16.BridgeCOUNTvalueAPERValueFieldReplay(&sealed) = replay
			*s16.BridgeCOUNTvalueAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s16.COUNTvalueAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c COUNTvalueValueCodec) EncodeAPER(value s16.COUNTvalueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s16.BridgeCOUNTvalueAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s16.BridgeCOUNTvalueAPERValueFieldContext(&value) == c.context && !fresh && (*s16.BridgeCOUNTvalueAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s16.BridgeCOUNTvalueAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s16.BridgeCOUNTvalueAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s16.BridgeCOUNTvalueAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c COUNTvalueValueCodec) encodeBudgetValue(value s16.COUNTvalue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c COUNTvalueValueCodec) encodeChanged(value s16.COUNTvalue,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CSGIdListItemValueCodec is the concrete ValueCodec[CSGIdListItem].
type CSGIdListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CSGIdListItem,

		error)
	encode func(CSGIdListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CSGIdListItem, aper.DecodeState,

	) (CSGIdListItem, aper.Snapshot,

	)
	compare func(CSGIdListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CSGIdListItemValueCodec) New(value CSGIdListItem,

) (CSGIdListItemAPERValue, error) {
	if c.encode == nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CSGIdListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CSGIdListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CSGIdListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CSGIdListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CSGIdListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CSGIdListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CSGIdListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CSGIdListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CSGIdListItemValueCodec) EncodeAPER(value CSGIdListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CSGIdListItemValueCodec) encodeBudgetValue(value CSGIdListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CSGIdListItemValueCodec) encodeChanged(value CSGIdListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CandidatePCIValueCodec is the concrete ValueCodec[CandidatePCI].
type CandidatePCIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CandidatePCI,

		error)
	encode func(CandidatePCI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CandidatePCI, aper.DecodeState,

	) (CandidatePCI, aper.Snapshot,

	)
	compare func(CandidatePCI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CandidatePCIValueCodec) New(value CandidatePCI,

) (CandidatePCIAPERValue, error) {
	if c.encode == nil {
		return CandidatePCIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CandidatePCIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CandidatePCIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CandidatePCIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CandidatePCIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CandidatePCIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CandidatePCIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CandidatePCIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CandidatePCIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CandidatePCIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CandidatePCIValueCodec) EncodeAPER(value CandidatePCIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CandidatePCIValueCodec) encodeBudgetValue(value CandidatePCI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CandidatePCIValueCodec) encodeChanged(value CandidatePCI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CandidatePCIListValueCodec is the concrete ValueCodec[CandidatePCIList].
type CandidatePCIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CandidatePCIList,

		error)
	encode func(CandidatePCIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CandidatePCIList, aper.DecodeState,

	) (CandidatePCIList, aper.Snapshot,

	)
	compare func(CandidatePCIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CandidatePCIListValueCodec) New(value CandidatePCIList,

) (CandidatePCIListAPERValue, error) {
	if c.encode == nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CandidatePCIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CandidatePCIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CandidatePCIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CandidatePCIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CandidatePCIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CandidatePCIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CandidatePCIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CandidatePCIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CandidatePCIListValueCodec) EncodeAPER(value CandidatePCIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CandidatePCIListValueCodec) encodeBudgetValue(value CandidatePCIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CandidatePCIListValueCodec) encodeChanged(value CandidatePCIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTypeValueCodec is the concrete ValueCodec[CellType].
type CellTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellType,

		error)
	encode func(CellType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellType, aper.DecodeState,

	) (CellType, aper.Snapshot,

	)
	compare func(CellType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTypeValueCodec) New(value CellType,

) (CellTypeAPERValue, error) {
	if c.encode == nil {
		return CellTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTypeValueCodec) EncodeAPER(value CellTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellTypeValueCodec) encodeBudgetValue(value CellType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTypeValueCodec) encodeChanged(value CellType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellsToActivateListValueCodec is the concrete ValueCodec[CellsToActivateList].
type CellsToActivateListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellsToActivateList,

		error)
	encode func(CellsToActivateList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellsToActivateList, aper.DecodeState,

	) (CellsToActivateList, aper.Snapshot,

	)
	compare func(CellsToActivateList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellsToActivateListValueCodec) New(value CellsToActivateList,

) (CellsToActivateListAPERValue, error) {
	if c.encode == nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellsToActivateListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellsToActivateListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellsToActivateListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellsToActivateListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellsToActivateListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellsToActivateListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellsToActivateListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellsToActivateListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellsToActivateListValueCodec) EncodeAPER(value CellsToActivateListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellsToActivateListValueCodec) encodeBudgetValue(value CellsToActivateList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellsToActivateListValueCodec) encodeChanged(value CellsToActivateList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellsToActivateListItemValueCodec is the concrete ValueCodec[CellsToActivateListItem].
type CellsToActivateListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellsToActivateListItem,

		error)
	encode func(CellsToActivateListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellsToActivateListItem, aper.DecodeState,

	) (CellsToActivateListItem, aper.Snapshot,

	)
	compare func(CellsToActivateListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellsToActivateListItemValueCodec) New(value CellsToActivateListItem,

) (CellsToActivateListItemAPERValue, error) {
	if c.encode == nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellsToActivateListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellsToActivateListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellsToActivateListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellsToActivateListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellsToActivateListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellsToActivateListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellsToActivateListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellsToActivateListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellsToActivateListItemValueCodec) EncodeAPER(value CellsToActivateListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CellsToActivateListItemValueCodec) encodeBudgetValue(value CellsToActivateListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellsToActivateListItemValueCodec) encodeChanged(value CellsToActivateListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEItemValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEItem].
type CriticalityDiagnosticsIEItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEItem,

		error)
	encode func(CriticalityDiagnosticsIEItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEItem, aper.DecodeState,

	) (CriticalityDiagnosticsIEItem, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEItemValueCodec) New(value CriticalityDiagnosticsIEItem,

) (CriticalityDiagnosticsIEItemAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEItemValueCodec) EncodeAPER(value CriticalityDiagnosticsIEItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEItemValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEItemValueCodec) encodeChanged(value CriticalityDiagnosticsIEItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CriticalityDiagnosticsIEListValueCodec is the concrete ValueCodec[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList,

		error)
	encode func(CriticalityDiagnosticsIEList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CriticalityDiagnosticsIEList, aper.DecodeState,

	) (CriticalityDiagnosticsIEList, aper.Snapshot,

	)
	compare func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CriticalityDiagnosticsIEListValueCodec) New(value CriticalityDiagnosticsIEList,

) (CriticalityDiagnosticsIEListAPERValue, error) {
	if c.encode == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CriticalityDiagnosticsIEListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CriticalityDiagnosticsIEListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CriticalityDiagnosticsIEListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CriticalityDiagnosticsIEListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CriticalityDiagnosticsIEListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CriticalityDiagnosticsIEListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CriticalityDiagnosticsIEListValueCodec) EncodeAPER(value CriticalityDiagnosticsIEListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c CriticalityDiagnosticsIEListValueCodec) encodeBudgetValue(value CriticalityDiagnosticsIEList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CriticalityDiagnosticsIEListValueCodec) encodeChanged(value CriticalityDiagnosticsIEList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoValueCodec is the concrete ValueCodec[DAPSResponseInfo].
type DAPSResponseInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfo,

		error)
	encode func(DAPSResponseInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfo, aper.DecodeState,

	) (DAPSResponseInfo, aper.Snapshot,

	)
	compare func(DAPSResponseInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoValueCodec) New(value DAPSResponseInfo,

) (DAPSResponseInfoAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoValueCodec) EncodeAPER(value DAPSResponseInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoValueCodec) encodeBudgetValue(value DAPSResponseInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoValueCodec) encodeChanged(value DAPSResponseInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DLCOUNTPDCPSNlengthValueCodec is the concrete ValueCodec[DLCOUNTPDCPSNlength].
type DLCOUNTPDCPSNlengthValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DLCOUNTPDCPSNlength,

		error)
	encode func(DLCOUNTPDCPSNlength,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DLCOUNTPDCPSNlength, aper.DecodeState,

	) (DLCOUNTPDCPSNlength, aper.Snapshot,

	)
	compare func(DLCOUNTPDCPSNlength, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLCOUNTPDCPSNlengthValueCodec) New(value DLCOUNTPDCPSNlength,

) (DLCOUNTPDCPSNlengthAPERValue, error) {
	if c.encode == nil {
		return DLCOUNTPDCPSNlengthAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DLCOUNTPDCPSNlengthAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLCOUNTPDCPSNlengthAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DLCOUNTPDCPSNlengthAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DLCOUNTPDCPSNlengthValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DLCOUNTPDCPSNlengthAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DLCOUNTPDCPSNlengthAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DLCOUNTPDCPSNlengthAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DLCOUNTPDCPSNlengthAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DLCOUNTPDCPSNlengthAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DLCOUNTPDCPSNlengthValueCodec) EncodeAPER(value DLCOUNTPDCPSNlengthAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DLCOUNTPDCPSNlengthValueCodec) encodeBudgetValue(value DLCOUNTPDCPSNlength,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLCOUNTPDCPSNlengthValueCodec) encodeChanged(value DLCOUNTPDCPSNlength,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DLDiscardingValueCodec is the concrete ValueCodec[DLDiscarding].
type DLDiscardingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DLDiscarding,

		error)
	encode func(DLDiscarding,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DLDiscarding, aper.DecodeState,

	) (DLDiscarding, aper.Snapshot,

	)
	compare func(DLDiscarding, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLDiscardingValueCodec) New(value DLDiscarding,

) (DLDiscardingAPERValue, error) {
	if c.encode == nil {
		return DLDiscardingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DLDiscardingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLDiscardingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DLDiscardingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DLDiscardingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DLDiscardingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DLDiscardingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DLDiscardingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DLDiscardingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DLDiscardingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DLDiscardingValueCodec) EncodeAPER(value DLDiscardingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DLDiscardingValueCodec) encodeBudgetValue(value DLDiscarding,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLDiscardingValueCodec) encodeChanged(value DLDiscarding,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEContainer is ProtocolIE-Container {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: a list of BearersSubjectToDLDiscardingItemIEField values.
type BearersSubjectToDLDiscardingItemIEContainer []BearersSubjectToDLDiscardingItemIEField

// BearersSubjectToEarlyStatusTransferItemIEContainer is ProtocolIE-Container {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: a list of BearersSubjectToEarlyStatusTransferItemIEField values.
type BearersSubjectToEarlyStatusTransferItemIEContainer []BearersSubjectToEarlyStatusTransferItemIEField

// DAPSResponseInfoListIEContainer is ProtocolIE-Container {{DAPSResponseInfoListIEs}} of TS 36.413: a list of DAPSResponseInfoListIEField values.
type DAPSResponseInfoListIEContainer []DAPSResponseInfoListIEField

// BearersSubjectToDLDiscardingItemAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItem].
type BearersSubjectToDLDiscardingItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToDLDiscardingItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItem].
type BearersSubjectToEarlyStatusTransferItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToEarlyStatusTransferItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// COUNTvaluePDCPSNlength18APERValue is the concrete APERValue[COUNTvaluePDCPSNlength18].
type COUNTvaluePDCPSNlength18APERValue struct {
	context s00.BridgeCodecContext
	Value   s16.COUNTvaluePDCPSNlength18

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v COUNTvaluePDCPSNlength18APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v COUNTvaluePDCPSNlength18APERValue) WithoutReplay() COUNTvaluePDCPSNlength18APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoItemAPERValue is the concrete APERValue[DAPSResponseInfoItem].
type DAPSResponseInfoItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfoItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoItemAPERValue) WithoutReplay() DAPSResponseInfoItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSRequestInfoAPERValue is the concrete APERValue[DAPSRequestInfo].
type DAPSRequestInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSRequestInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSRequestInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSRequestInfoAPERValue) WithoutReplay() DAPSRequestInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingListAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingList].
type BearersSubjectToDLDiscardingListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToDLDiscardingList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingListAPERValue) WithoutReplay() BearersSubjectToDLDiscardingListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseAPERValue is the concrete APERValue[Cause].
type CauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   Cause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CauseAPERValue) WithoutReplay() CauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListAPERValue is the concrete APERValue[DAPSResponseInfoList].
type DAPSResponseInfoListAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfoList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListAPERValue) WithoutReplay() DAPSResponseInfoListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLCPSecurityInformationAPERValue is the concrete APERValue[DLCPSecurityInformation].
type DLCPSecurityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   DLCPSecurityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DLCPSecurityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCPSecurityInformationAPERValue) WithoutReplay() DLCPSecurityInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGMembershipInfoAPERValue is the concrete APERValue[CSGMembershipInfo].
type CSGMembershipInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGMembershipInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGMembershipInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGMembershipInfoAPERValue) WithoutReplay() CSGMembershipInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListAPERValue is the concrete APERValue[CSGIdList].
type CSGIdListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGIdList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListAPERValue) WithoutReplay() CSGIdListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// Cdma2000OneXSRVCCInfoAPERValue is the concrete APERValue[Cdma2000OneXSRVCCInfo].
type Cdma2000OneXSRVCCInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   Cdma2000OneXSRVCCInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v Cdma2000OneXSRVCCInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Cdma2000OneXSRVCCInfoAPERValue) WithoutReplay() Cdma2000OneXSRVCCInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferListAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferList].
type BearersSubjectToEarlyStatusTransferListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToEarlyStatusTransferList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferListAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CSGIdListItemAPERValue is the concrete APERValue[CSGIdListItem].
type CSGIdListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CSGIdListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CSGIdListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CSGIdListItemAPERValue) WithoutReplay() CSGIdListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CandidatePCIAPERValue is the concrete APERValue[CandidatePCI].
type CandidatePCIAPERValue struct {
	context s00.BridgeCodecContext
	Value   CandidatePCI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CandidatePCIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CandidatePCIAPERValue) WithoutReplay() CandidatePCIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CandidatePCIListAPERValue is the concrete APERValue[CandidatePCIList].
type CandidatePCIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CandidatePCIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CandidatePCIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CandidatePCIListAPERValue) WithoutReplay() CandidatePCIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTypeAPERValue is the concrete APERValue[CellType].
type CellTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTypeAPERValue) WithoutReplay() CellTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellsToActivateListAPERValue is the concrete APERValue[CellsToActivateList].
type CellsToActivateListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellsToActivateList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellsToActivateListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellsToActivateListAPERValue) WithoutReplay() CellsToActivateListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellsToActivateListItemAPERValue is the concrete APERValue[CellsToActivateListItem].
type CellsToActivateListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellsToActivateListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellsToActivateListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellsToActivateListItemAPERValue) WithoutReplay() CellsToActivateListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEItemAPERValue is the concrete APERValue[CriticalityDiagnosticsIEItem].
type CriticalityDiagnosticsIEItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEItemAPERValue) WithoutReplay() CriticalityDiagnosticsIEItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityDiagnosticsIEListAPERValue is the concrete APERValue[CriticalityDiagnosticsIEList].
type CriticalityDiagnosticsIEListAPERValue struct {
	context s00.BridgeCodecContext
	Value   CriticalityDiagnosticsIEList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CriticalityDiagnosticsIEListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CriticalityDiagnosticsIEListAPERValue) WithoutReplay() CriticalityDiagnosticsIEListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoAPERValue is the concrete APERValue[DAPSResponseInfo].
type DAPSResponseInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   DAPSResponseInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoAPERValue) WithoutReplay() DAPSResponseInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLCOUNTPDCPSNlengthAPERValue is the concrete APERValue[DLCOUNTPDCPSNlength].
type DLCOUNTPDCPSNlengthAPERValue struct {
	context s00.BridgeCodecContext
	Value   DLCOUNTPDCPSNlength

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DLCOUNTPDCPSNlengthAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLCOUNTPDCPSNlengthAPERValue) WithoutReplay() DLCOUNTPDCPSNlengthAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLDiscardingAPERValue is the concrete APERValue[DLDiscarding].
type DLDiscardingAPERValue struct {
	context s00.BridgeCodecContext
	Value   DLDiscarding

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DLDiscardingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DLDiscardingAPERValue) WithoutReplay() DLDiscardingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemIEValueERABIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, error)
	encode  func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) New(value BearersSubjectToDLDiscardingItemIEValueERABIEContainerList) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToDLDiscardingItemIEValueERABIEContainerList []BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer

// BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) New(value BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList []BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer

// DAPSResponseInfoListIEValueERABIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueERABIEContainerList].
type DAPSResponseInfoListIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueERABIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueERABIEContainerList) (DAPSResponseInfoListIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueERABIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueERABIEContainerList is E-RAB-IE-ContainerList {{DAPSResponseInfoListIEs}} of TS 36.413: a list of information element fields.
type DAPSResponseInfoListIEValueERABIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// BearersSubjectToDLDiscardingItemIEFieldValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemIEField].
type BearersSubjectToDLDiscardingItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEField, error)
	encode  func(BearersSubjectToDLDiscardingItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemIEField, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEField, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemIEFieldValueCodec) New(value BearersSubjectToDLDiscardingItemIEField) (BearersSubjectToDLDiscardingItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemIEFieldValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemIEFieldValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemIEFieldValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemIEField].
type BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEField, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemIEField, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) New(value BearersSubjectToEarlyStatusTransferItemIEField) (BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEFieldValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEField].
type DAPSResponseInfoListIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEField, error)
	encode  func(DAPSResponseInfoListIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEField, aper.DecodeState) (DAPSResponseInfoListIEField, aper.Snapshot)
	compare func(DAPSResponseInfoListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEFieldValueCodec) New(value DAPSResponseInfoListIEField) (DAPSResponseInfoListIEFieldAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEFieldValueCodec) EncodeAPER(value DAPSResponseInfoListIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEFieldValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEFieldValueCodec) encodeChanged(value DAPSResponseInfoListIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEContainerValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemIEContainer].
type BearersSubjectToDLDiscardingItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEContainer, error)
	encode  func(BearersSubjectToDLDiscardingItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemIEContainer, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemIEContainerValueCodec) New(value BearersSubjectToDLDiscardingItemIEContainer) (BearersSubjectToDLDiscardingItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemIEContainerValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemIEContainerValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemIEContainerValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemIEContainer].
type BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEContainer, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemIEContainer, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) New(value BearersSubjectToEarlyStatusTransferItemIEContainer) (BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEContainerValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEContainer].
type DAPSResponseInfoListIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEContainer, error)
	encode  func(DAPSResponseInfoListIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEContainer, aper.DecodeState) (DAPSResponseInfoListIEContainer, aper.Snapshot)
	compare func(DAPSResponseInfoListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEContainerValueCodec) New(value DAPSResponseInfoListIEContainer) (DAPSResponseInfoListIEContainerAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEContainerValueCodec) EncodeAPER(value DAPSResponseInfoListIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEContainerValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEContainerValueCodec) encodeChanged(value DAPSResponseInfoListIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, error)
	encode  func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) New(value BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList []BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) New(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList []BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer

// DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueProtocolErrorIEContainerList].
type DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList) (DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{DAPSResponseInfoListIEs}} of TS 36.413: a list of information element fields.
type DAPSResponseInfoListIEValueProtocolErrorIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, error)
	encode  func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) New(value BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToDLDiscarding-ItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList []BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, error)
	encode  func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) New(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToEarlyStatusTransfer-ItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList []BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer

// DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[DAPSResponseInfoListIEValueProtocolIEContainerList].
type DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, error)
	encode  func(DAPSResponseInfoListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) New(value DAPSResponseInfoListIEValueProtocolIEContainerList) (DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) encodeChanged(value DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {DAPSResponseInfoListIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type DAPSResponseInfoListIEValueProtocolIEContainerList []DAPSResponseInfoListIEValueProtocolIESingleContainer

// BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemIEValueERABIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEValueERABIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueERABIEContainerList].
type DAPSResponseInfoListIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueERABIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemIEFieldAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemIEField].
type BearersSubjectToDLDiscardingItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEFieldAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemIEField].
type BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEFieldAPERValue is the concrete APERValue[DAPSResponseInfoListIEField].
type DAPSResponseInfoListIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEFieldAPERValue) WithoutReplay() DAPSResponseInfoListIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemIEContainerAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemIEContainer].
type BearersSubjectToDLDiscardingItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEContainerAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemIEContainer].
type BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEContainerAPERValue is the concrete APERValue[DAPSResponseInfoListIEContainer].
type DAPSResponseInfoListIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEContainerAPERValue) WithoutReplay() DAPSResponseInfoListIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueProtocolErrorIEContainerList].
type DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList].
type BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue is the concrete APERValue[DAPSResponseInfoListIEValueProtocolIEContainerList].
type DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DAPSResponseInfoListIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue) WithoutReplay() DAPSResponseInfoListIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingItem(v *BearersSubjectToDLDiscardingItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APDLDiscarding(&v.DLDiscarding, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingItem(v *BearersSubjectToDLDiscardingItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APDLDiscarding(&v.DLDiscarding, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingItemIEValue(v *BearersSubjectToDLDiscardingItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(351):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingItem == nil)
				if v.rowBearersSubjectToDLDiscardingItem != nil {
					BridgeCaptureS1APBearersSubjectToDLDiscardingItem(v.rowBearersSubjectToDLDiscardingItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToDLDiscardingItemIEValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToDLDiscardingItemIEValue {
	BridgeCaptureS1APBearersSubjectToDLDiscardingItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToDLDiscardingItemIEValue(v *BearersSubjectToDLDiscardingItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(351):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingItem == nil)
				if v.rowBearersSubjectToDLDiscardingItem != nil {
					BridgeCompareS1APBearersSubjectToDLDiscardingItem(v.rowBearersSubjectToDLDiscardingItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToDLDiscardingItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToDLDiscardingItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItemIEValue(v *BearersSubjectToEarlyStatusTransferItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(322):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToEarlyStatusTransferItem == nil)
				if v.rowBearersSubjectToEarlyStatusTransferItem != nil {
					BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(v.rowBearersSubjectToEarlyStatusTransferItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToEarlyStatusTransferItemIEValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToEarlyStatusTransferItemIEValue {
	BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferItemIEValue(v *BearersSubjectToEarlyStatusTransferItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(322):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToEarlyStatusTransferItem == nil)
				if v.rowBearersSubjectToEarlyStatusTransferItem != nil {
					BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v.rowBearersSubjectToEarlyStatusTransferItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToEarlyStatusTransferItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToEarlyStatusTransferItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APCSGIdListItem(v *CSGIdListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCSGId(&v.CSGId, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCSGIdListItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGIdListItem(v *CSGIdListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCSGId(&v.CSGId, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCSGIdListItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCSGMembershipInfo(v *CSGMembershipInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCSGMembershipStatus(&v.CSGMembershipStatus, s)
	s00.BridgeCaptureS1APCSGId(&v.CSGId, s)
	{
		f := s.Begin()
		s.Bool(v.CellAccessMode == nil)
		if v.CellAccessMode != nil {
			s00.BridgeCaptureS1APCellAccessMode(v.CellAccessMode, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PLMNidentity == nil)
		if v.PLMNidentity != nil {
			s00.BridgeCaptureS1APPLMNidentity(v.PLMNidentity, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCSGMembershipInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGMembershipInfo(v *CSGMembershipInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCSGMembershipStatus(&v.CSGMembershipStatus, s)
	s02.BridgeCompareS1APCSGId(&v.CSGId, s)
	{
		f := s.Begin()
		s.Bool(v.CellAccessMode == nil)
		if v.CellAccessMode != nil {
			s02.BridgeCompareS1APCellAccessMode(v.CellAccessMode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PLMNidentity == nil)
		if v.PLMNidentity != nil {
			s08.BridgeCompareS1APPLMNidentity(v.PLMNidentity, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCSGMembershipInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidatePCI(v *CandidatePCI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PCI))
	s.Bytes(v.EARFCN)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidatePCI(v *CandidatePCI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.PCI))
	s.Bytes(v.EARFCN)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCause(v *Cause, s *aper.SemanticCapture) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s00.BridgeCaptureS1APCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceTransport:
		{
			f := s.Begin()
			s.Bool(v.Transport == nil)
			if v.Transport != nil {
				s00.BridgeCaptureS1APCauseTransport(v.Transport, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceNas:
		{
			f := s.Begin()
			s.Bool(v.Nas == nil)
			if v.Nas != nil {
				s00.BridgeCaptureS1APCauseNas(v.Nas, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s00.BridgeCaptureS1APCauseProtocol(v.Protocol, s)
			}
			s.End(f, nil, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s00.BridgeCaptureS1APCauseMisc(v.Misc, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCause(v *Cause, s *aper.SemanticComparison) {
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
	case s00.CauseChoiceRadioNetwork:
		{
			f := s.Begin()
			s.Bool(v.RadioNetwork == nil)
			if v.RadioNetwork != nil {
				s02.BridgeCompareS1APCauseRadioNetwork(v.RadioNetwork, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceTransport:
		{
			f := s.Begin()
			s.Bool(v.Transport == nil)
			if v.Transport != nil {
				s02.BridgeCompareS1APCauseTransport(v.Transport, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceNas:
		{
			f := s.Begin()
			s.Bool(v.Nas == nil)
			if v.Nas != nil {
				s02.BridgeCompareS1APCauseNas(v.Nas, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceProtocol:
		{
			f := s.Begin()
			s.Bool(v.Protocol == nil)
			if v.Protocol != nil {
				s02.BridgeCompareS1APCauseProtocol(v.Protocol, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.CauseChoiceMisc:
		{
			f := s.Begin()
			s.Bool(v.Misc == nil)
			if v.Misc != nil {
				s02.BridgeCompareS1APCauseMisc(v.Misc, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCdma2000OneXSRVCCInfo(v *Cdma2000OneXSRVCCInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCdma2000OneXMEID(&v.Cdma2000OneXMEID, s)
	s00.BridgeCaptureS1APCdma2000OneXMSI(&v.Cdma2000OneXMSI, s)
	s00.BridgeCaptureS1APCdma2000OneXPilot(&v.Cdma2000OneXPilot, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCdma2000OneXSRVCCInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCdma2000OneXSRVCCInfo(v *Cdma2000OneXSRVCCInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCdma2000OneXMEID(&v.Cdma2000OneXMEID, s)
	s02.BridgeCompareS1APCdma2000OneXMSI(&v.Cdma2000OneXMSI, s)
	s02.BridgeCompareS1APCdma2000OneXPilot(&v.Cdma2000OneXPilot, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCdma2000OneXSRVCCInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellType(v *CellType, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCellSize(&v.CellSize, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellTypeExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellType(v *CellType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCellSize(&v.CellSize, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellTypeExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellsToActivateListItem(v *CellsToActivateListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellsToActivateListItem(v *CellsToActivateListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCriticalityDiagnosticsIEItem(v *CriticalityDiagnosticsIEItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APCriticality(&v.IECriticality, s)
	s00.BridgeCaptureS1APProtocolIEID(&v.IEID, s)
	s00.BridgeCaptureS1APTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCriticalityDiagnosticsIEItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnosticsIEItem(v *CriticalityDiagnosticsIEItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APCriticality(&v.IECriticality, s)
	s03.BridgeCompareS1APProtocolIEID(&v.IEID, s)
	s08.BridgeCompareS1APTypeOfError(&v.TypeOfError, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCriticalityDiagnosticsIEItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSRequestInfo(v *DAPSRequestInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.DAPSIndicator))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSRequestInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSRequestInfo(v *DAPSRequestInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.DAPSIndicator))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSRequestInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfo(v *DAPSResponseInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Dapsresponseindicator))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSResponseInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSResponseInfo(v *DAPSResponseInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Dapsresponseindicator))
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSResponseInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoItem(v *DAPSResponseInfoItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	BridgeCaptureS1APDAPSResponseInfo(&v.DAPSResponseInfo, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSResponseInfoItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSResponseInfoItem(v *DAPSResponseInfoItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	BridgeCompareS1APDAPSResponseInfo(&v.DAPSResponseInfo, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDAPSResponseInfoItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoListIEValue(v *DAPSResponseInfoListIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(319):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoItem == nil)
				if v.rowDAPSResponseInfoItem != nil {
					BridgeCaptureS1APDAPSResponseInfoItem(v.rowDAPSResponseInfoItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DAPSResponseInfoListIEValue) captureSemantics(s aper.SemanticCapture) DAPSResponseInfoListIEValue {
	BridgeCaptureS1APDAPSResponseInfoListIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDAPSResponseInfoListIEValue(v *DAPSResponseInfoListIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(319):
			{
				f := s.Begin()
				s.Bool(v.rowDAPSResponseInfoItem == nil)
				if v.rowDAPSResponseInfoItem != nil {
					BridgeCompareS1APDAPSResponseInfoItem(v.rowDAPSResponseInfoItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DAPSResponseInfoListIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDAPSResponseInfoListIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APDLCOUNTPDCPSNlength(v *DLCOUNTPDCPSNlength, s *aper.SemanticCapture) {
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
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength12 == nil)
			if v.DLCOUNTValuePDCPSNlength12 != nil {
				s16.BridgeCaptureS1APCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength15 == nil)
			if v.DLCOUNTValuePDCPSNlength15 != nil {
				s16.BridgeCaptureS1APCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength18 == nil)
			if v.DLCOUNTValuePDCPSNlength18 != nil {
				s16.BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDLCOUNTPDCPSNlength(v *DLCOUNTPDCPSNlength, s *aper.SemanticComparison) {
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
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength12 == nil)
			if v.DLCOUNTValuePDCPSNlength12 != nil {
				s16.BridgeCompareS1APCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength15 == nil)
			if v.DLCOUNTValuePDCPSNlength15 != nil {
				s16.BridgeCompareS1APCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DLCOUNTValuePDCPSNlength18 == nil)
			if v.DLCOUNTValuePDCPSNlength18 != nil {
				s16.BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDLCPSecurityInformation(v *DLCPSecurityInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APDLNASMAC(&v.DlNASMAC, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDLCPSecurityInformation(v *DLCPSecurityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APDLNASMAC(&v.DlNASMAC, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDLDiscarding(v *DLDiscarding, s *aper.SemanticCapture) {
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
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength12 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength12 != nil {
				s16.BridgeCaptureS1APCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength15 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
				s16.BridgeCaptureS1APCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength18 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
				s16.BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDLDiscarding(v *DLDiscarding, s *aper.SemanticComparison) {
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
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength12 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength12 != nil {
				s16.BridgeCompareS1APCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength15 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
				s16.BridgeCompareS1APCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength18 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
				s16.BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}

type BearersSubjectToEarlyStatusTransferList = []BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer

// BearersSubjectToEarlyStatusTransferItem represents the ASN.1 type Bearers-SubjectToEarlyStatusTransfer-Item (SEQUENCE).
type BearersSubjectToEarlyStatusTransferItem struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	ERABID              s00.ERABID                                                    `asn1:"tag:0,context,implicit"`
	DLCOUNTPDCPSNlength DLCOUNTPDCPSNlength                                           `asn1:"tag:1,context,explicit"`
	IEExtensions        s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                                          `asn1:"-" json:"-"`
	extCount            int64                                                         `asn1:"-" json:"-"`
	extPresent          []bool                                                        `asn1:"-" json:"-"`
	extData             [][]byte                                                      `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                                             `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                                        `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}
type BearersSubjectToDLDiscardingList = []BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer

// BearersSubjectToDLDiscardingItem represents the ASN.1 type Bearers-SubjectToDLDiscarding-Item (SEQUENCE).
type BearersSubjectToDLDiscardingItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                             `asn1:"tag:0,context,implicit"`
	DLDiscarding      DLDiscarding                                           `asn1:"tag:1,context,explicit"`
	IEExtensions      s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                   `asn1:"-" json:"-"`
	extCount          int64                                                  `asn1:"-" json:"-"`
	extPresent        []bool                                                 `asn1:"-" json:"-"`
	extData           [][]byte                                               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// Cause represents the ASN.1 CHOICE type Cause.
type Cause struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding   `json:"-"`
	perOpenTypePadding aper.CompletePadding   `json:"-"`
	UnknownExtension   *aper.ChoiceExtension  `json:"UnknownExtension,omitempty"`
	RadioNetwork       *s00.CauseRadioNetwork `json:"RadioNetwork,omitempty"`
	Transport          *s00.CauseTransport    `json:"Transport,omitempty"`
	Nas                *s00.CauseNas          `json:"Nas,omitempty"`
	Protocol           *s00.CauseProtocol     `json:"Protocol,omitempty"`
	Misc               *s00.CauseMisc         `json:"Misc,omitempty"`
}

// Cdma2000OneXSRVCCInfo represents the ASN.1 type Cdma2000OneXSRVCCInfo (SEQUENCE).
type Cdma2000OneXSRVCCInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	Cdma2000OneXMEID  s00.Cdma2000OneXMEID                        `asn1:"tag:0,context,implicit"`
	Cdma2000OneXMSI   s00.Cdma2000OneXMSI                         `asn1:"tag:1,context,implicit"`
	Cdma2000OneXPilot s00.Cdma2000OneXPilot                       `asn1:"tag:2,context,implicit"`
	IEExtensions      s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// CellType represents the ASN.1 type CellType (SEQUENCE).
type CellType struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	CellSize          s00.CellSize                   `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.CellTypeExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                           `asn1:"-" json:"-"`
	extCount          int64                          `asn1:"-" json:"-"`
	extPresent        []bool                         `asn1:"-" json:"-"`
	extData           [][]byte                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CSGIdList = []CSGIdListItem

// CSGIdListItem represents the ASN.1 type CSG-IdList-Item (SEQUENCE).
type CSGIdListItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	CSGId             s00.CSGId                           `asn1:"tag:0,context,implicit"`
	IEExtensions      s08.CSGIdListItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                `asn1:"-" json:"-"`
	extCount          int64                               `asn1:"-" json:"-"`
	extPresent        []bool                              `asn1:"-" json:"-"`
	extData           [][]byte                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type CriticalityDiagnosticsIEList = []CriticalityDiagnosticsIEItem

// CriticalityDiagnosticsIEItem represents the ASN.1 type CriticalityDiagnostics-IE-Item (SEQUENCE).
type CriticalityDiagnosticsIEItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	IECriticality     s00.Criticality                                    `asn1:"tag:0,context,implicit"`
	IEID              s00.ProtocolIEID                                   `asn1:"tag:1,context,implicit"`
	TypeOfError       s00.TypeOfError                                    `asn1:"tag:2,context,implicit"`
	IEExtensions      s09.CriticalityDiagnosticsIEItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// DAPSRequestInfo represents the ASN.1 type DAPSRequestInfo (SEQUENCE).
type DAPSRequestInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	DAPSIndicator     int64                                 `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.DAPSRequestInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type DAPSResponseInfoList = []DAPSResponseInfoListIEValueProtocolIESingleContainer

// DAPSResponseInfoItem represents the ASN.1 type DAPSResponseInfoItem (SEQUENCE).
type DAPSResponseInfoItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                 `asn1:"tag:0,context,implicit"`
	DAPSResponseInfo  DAPSResponseInfo                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.DAPSResponseInfoItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                       `asn1:"-" json:"-"`
	extCount          int64                                      `asn1:"-" json:"-"`
	extPresent        []bool                                     `asn1:"-" json:"-"`
	extData           [][]byte                                   `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// DAPSResponseInfo represents the ASN.1 type DAPSResponseInfo (SEQUENCE).
type DAPSResponseInfo struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	Dapsresponseindicator int64                                  `asn1:"tag:0,context,implicit"`
	IEExtensions          s09.DAPSResponseInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                   `asn1:"-" json:"-"`
	extCount              int64                                  `asn1:"-" json:"-"`
	extPresent            []bool                                 `asn1:"-" json:"-"`
	extData               [][]byte                               `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// DLCPSecurityInformation represents the ASN.1 type DL-CP-SecurityInformation (SEQUENCE).
type DLCPSecurityInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	DlNASMAC          s00.DLNASMAC                                  `asn1:"tag:0,context,implicit"`
	IEExtensions      s09.DLCPSecurityInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// DLCOUNTPDCPSNlength represents the ASN.1 CHOICE type DLCOUNT-PDCP-SNlength.
type DLCOUNTPDCPSNlength struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	received                   bool
	withoutReplay              bool
	receivedAbsolute           bool
	receivedBytes              aper.WireSpan
	receivedLocation           aper.Location
	Choice                     int
	perPadding                 aper.CompletePadding          `json:"-"`
	perOpenTypePadding         aper.CompletePadding          `json:"-"`
	UnknownExtension           *aper.ChoiceExtension         `json:"UnknownExtension,omitempty"`
	DLCOUNTValuePDCPSNlength12 *s16.COUNTvalue               `json:"DLCOUNTValuePDCPSNlength12,omitempty"`
	DLCOUNTValuePDCPSNlength15 *s16.COUNTValueExtended       `json:"DLCOUNTValuePDCPSNlength15,omitempty"`
	DLCOUNTValuePDCPSNlength18 *s16.COUNTvaluePDCPSNlength18 `json:"DLCOUNTValuePDCPSNlength18,omitempty"`
}

// DLDiscarding represents the ASN.1 CHOICE type DLDiscarding.
type DLDiscarding struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	Choice                            int
	perPadding                        aper.CompletePadding          `json:"-"`
	perOpenTypePadding                aper.CompletePadding          `json:"-"`
	UnknownExtension                  *aper.ChoiceExtension         `json:"UnknownExtension,omitempty"`
	DiscardDLCOUNTValuePDCPSNlength12 *s16.COUNTvalue               `json:"DiscardDLCOUNTValuePDCPSNlength12,omitempty"`
	DiscardDLCOUNTValuePDCPSNlength15 *s16.COUNTValueExtended       `json:"DiscardDLCOUNTValuePDCPSNlength15,omitempty"`
	DiscardDLCOUNTValuePDCPSNlength18 *s16.COUNTvaluePDCPSNlength18 `json:"DiscardDLCOUNTValuePDCPSNlength18,omitempty"`
}

// MarshalAPER encodes BearersSubjectToEarlyStatusTransferItem to APER format.
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.DLCOUNTPDCPSNlength.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dLCOUNT-PDCP-SNlength: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToEarlyStatusTransferItem from APER format.
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	bb.EnterComponent("BearersSubjectToEarlyStatusTransferItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	v.perPadding = padding
	return nil
}
func (v *BearersSubjectToEarlyStatusTransferItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToEarlyStatusTransferItem{}
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
	toleranceMark_dlcountpdcpsnlength := bb.EnterComponent("DLCOUNTPDCPSNlength")
	if err := v.DLCOUNTPDCPSNlength.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	bb.LeaveComponent(toleranceMark_dlcountpdcpsnlength)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.BearersSubjectToEarlyStatusTransferItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes BearersSubjectToDLDiscardingItem to APER format.
func (v *BearersSubjectToDLDiscardingItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.DLDiscarding.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dL-Discarding: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToDLDiscardingItem from APER format.
func (v *BearersSubjectToDLDiscardingItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BearersSubjectToDLDiscardingItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItem")
	}
	bb.EnterComponent("BearersSubjectToDLDiscardingItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItem")
	}
	v.perPadding = padding
	return nil
}
func (v *BearersSubjectToDLDiscardingItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToDLDiscardingItem{}
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
	toleranceMark_dldiscarding := bb.EnterComponent("DLDiscarding")
	if err := v.DLDiscarding.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLDiscarding")
	}
	bb.LeaveComponent(toleranceMark_dldiscarding)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.BearersSubjectToDLDiscardingItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.BearersSubjectToDLDiscardingItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes Cause to APER format.
func (v *Cause) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *Cause) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "Cause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "Cause:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "Cause:", v.Choice)
	}
	isExtension := v.Choice > 5
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "Cause:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 4); err != nil {
		return err
	}
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		if v.RadioNetwork == nil {
			return fmt.Errorf("choice alternative radioNetwork is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.RadioNetwork), 36, true); err != nil {
			return fmt.Errorf("encoding radioNetwork: %w", err)
		}
	case s00.CauseChoiceTransport:
		if v.Transport == nil {
			return fmt.Errorf("choice alternative transport is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Transport), 2, true); err != nil {
			return fmt.Errorf("encoding transport: %w", err)
		}
	case s00.CauseChoiceNas:
		if v.Nas == nil {
			return fmt.Errorf("choice alternative nas is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Nas), 4, true); err != nil {
			return fmt.Errorf("encoding nas: %w", err)
		}
	case s00.CauseChoiceProtocol:
		if v.Protocol == nil {
			return fmt.Errorf("choice alternative protocol is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Protocol), 7, true); err != nil {
			return fmt.Errorf("encoding protocol: %w", err)
		}
	case s00.CauseChoiceMisc:
		if v.Misc == nil {
			return fmt.Errorf("choice alternative misc is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Misc), 6, true); err != nil {
			return fmt.Errorf("encoding misc: %w", err)
		}
	default:
		return fmt.Errorf("unknown Cause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes Cause from APER format.
func (v *Cause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *Cause) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	bb.EnterComponent("Cause")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	padding, err := aper.CaptureFinalBits(bb, "Cause")
	if err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *Cause) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cause{}
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
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 4)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.CauseChoiceRadioNetwork:
		val_radionetwork, err := aper.DecodeEnumeratedAligned(bb, 36, true, aper.EnumerationSource{KnownExtensions: 9, Path: "RadioNetwork"})
		if err != nil {
			return runtime.WrapDecodePath(err, "RadioNetwork")
		}
		tmp_radionetwork := s00.CauseRadioNetwork(val_radionetwork)
		if err := aper.ChargeValue(bb, tmp_radionetwork); err != nil {
			return err
		}
		v.RadioNetwork = (*s00.CauseRadioNetwork)(bb.OwnInt64(int64(tmp_radionetwork)))

	case s00.CauseChoiceTransport:
		val_transport, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Transport"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Transport")
		}
		tmp_transport := s00.CauseTransport(val_transport)
		if err := aper.ChargeValue(bb, tmp_transport); err != nil {
			return err
		}
		v.Transport = (*s00.CauseTransport)(bb.OwnInt64(int64(tmp_transport)))

	case s00.CauseChoiceNas:
		val_nas, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 3, Path: "Nas"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Nas")
		}
		tmp_nas := s00.CauseNas(val_nas)
		if err := aper.ChargeValue(bb, tmp_nas); err != nil {
			return err
		}
		v.Nas = (*s00.CauseNas)(bb.OwnInt64(int64(tmp_nas)))

	case s00.CauseChoiceProtocol:
		val_protocol, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Protocol"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Protocol")
		}
		tmp_protocol := s00.CauseProtocol(val_protocol)
		if err := aper.ChargeValue(bb, tmp_protocol); err != nil {
			return err
		}
		v.Protocol = (*s00.CauseProtocol)(bb.OwnInt64(int64(tmp_protocol)))

	case s00.CauseChoiceMisc:
		val_misc, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Misc"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Misc")
		}
		tmp_misc := s00.CauseMisc(val_misc)
		if err := aper.ChargeValue(bb, tmp_misc); err != nil {
			return err
		}
		v.Misc = (*s00.CauseMisc)(bb.OwnInt64(int64(tmp_misc)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes Cdma2000OneXSRVCCInfo to APER format.
func (v *Cdma2000OneXSRVCCInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXMEID), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXMEID: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXMSI), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXMSI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.Cdma2000OneXPilot), 0, 0, false); err != nil {
		return fmt.Errorf("encoding cdma2000OneXPilot: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes Cdma2000OneXSRVCCInfo from APER format.
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	bb.EnterComponent("Cdma2000OneXSRVCCInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "Cdma2000OneXSRVCCInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
	}
	v.perPadding = padding
	return nil
}
func (v *Cdma2000OneXSRVCCInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Cdma2000OneXSRVCCInfo{}
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
	val_cdma2000onexmeid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXMEID")
	}
	v.Cdma2000OneXMEID = s00.Cdma2000OneXMEID(val_cdma2000onexmeid)
	val_cdma2000onexmsi, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXMSI")
	}
	v.Cdma2000OneXMSI = s00.Cdma2000OneXMSI(val_cdma2000onexmsi)
	val_cdma2000onexpilot, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Cdma2000OneXPilot")
	}
	v.Cdma2000OneXPilot = s00.Cdma2000OneXPilot(val_cdma2000onexpilot)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.Cdma2000OneXSRVCCInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.Cdma2000OneXSRVCCInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCdma2000OneXSRVCCInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CellType to APER format.
func (v *CellType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CellSize), 4, true); err != nil {
		return fmt.Errorf("encoding cell-Size: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCellTypeExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellType from APER format.
func (v *CellType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	bb.EnterComponent("CellType")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellType")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellType")
	}
	v.perPadding = padding
	return nil
}
func (v *CellType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellType{}
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
	val_cellsize, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellSize"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CellSize")
	}
	v.CellSize = s00.CellSize(val_cellsize)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CellTypeExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CellTypeExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCellTypeExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CSGIdListItem to APER format.
func (v *CSGIdListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CSGIdListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAligned(bb, v.CSGId.Bytes, v.CSGId.BitLength, 27, 27, true); err != nil {
		return fmt.Errorf("encoding cSG-Id: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CSGIdListItem from APER format.
func (v *CSGIdListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CSGIdListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	bb.EnterComponent("CSGIdListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGIdListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdListItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CSGIdListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGIdListItem{}
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
	bsBytes_csgid, bsBitLen_csgid, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGId")
	}
	v.CSGId = runtime.BitString{Bytes: bsBytes_csgid, BitLength: bsBitLen_csgid}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CSGIdListItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CSGIdListItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCSGIdListItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes CriticalityDiagnosticsIEItem to APER format.
func (v *CriticalityDiagnosticsIEItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.IECriticality), 3, false); err != nil {
		return fmt.Errorf("encoding iECriticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.IEID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding iE-ID: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.TypeOfError), 2, true); err != nil {
		return fmt.Errorf("encoding typeOfError: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CriticalityDiagnosticsIEItem from APER format.
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	bb.EnterComponent("CriticalityDiagnosticsIEItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CriticalityDiagnosticsIEItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CriticalityDiagnosticsIEItem{}
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
	val_iecriticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "IECriticality"})
	if err != nil {
		return runtime.WrapDecodePath(err, "IECriticality")
	}
	v.IECriticality = s00.Criticality(val_iecriticality)
	val_ieid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "IEID")
	}
	v.IEID = s00.ProtocolIEID(val_ieid)
	val_typeoferror, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TypeOfError"})
	if err != nil {
		return runtime.WrapDecodePath(err, "TypeOfError")
	}
	v.TypeOfError = s00.TypeOfError(val_typeoferror)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.CriticalityDiagnosticsIEItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.CriticalityDiagnosticsIEItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeCriticalityDiagnosticsIEItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSRequestInfo to APER format.
func (v *DAPSRequestInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSRequestInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.DAPSIndicator), 1, true); err != nil {
		return fmt.Errorf("encoding dAPSIndicator: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSRequestInfo from APER format.
func (v *DAPSRequestInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DAPSRequestInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	bb.EnterComponent("DAPSRequestInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSRequestInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSRequestInfo")
	}
	v.perPadding = padding
	return nil
}
func (v *DAPSRequestInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSRequestInfo{}
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
	val_dapsindicator, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DAPSIndicator"})
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSIndicator")
	}
	v.DAPSIndicator = val_dapsindicator
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.DAPSRequestInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.DAPSRequestInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeDAPSRequestInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSResponseInfoItem to APER format.
func (v *DAPSResponseInfoItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSResponseInfoItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := v.DAPSResponseInfo.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dAPSResponseInfo: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSResponseInfoItem from APER format.
func (v *DAPSResponseInfoItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DAPSResponseInfoItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	bb.EnterComponent("DAPSResponseInfoItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
	}
	v.perPadding = padding
	return nil
}
func (v *DAPSResponseInfoItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfoItem{}
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
	toleranceMark_dapsresponseinfo := bb.EnterComponent("DAPSResponseInfo")
	if err := v.DAPSResponseInfo.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	bb.LeaveComponent(toleranceMark_dapsresponseinfo)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.DAPSResponseInfoItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.DAPSResponseInfoItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeDAPSResponseInfoItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DAPSResponseInfo to APER format.
func (v *DAPSResponseInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DAPSResponseInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Dapsresponseindicator), 2, true); err != nil {
		return fmt.Errorf("encoding dapsresponseindicator: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DAPSResponseInfo from APER format.
func (v *DAPSResponseInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DAPSResponseInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	bb.EnterComponent("DAPSResponseInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSResponseInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfo")
	}
	v.perPadding = padding
	return nil
}
func (v *DAPSResponseInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DAPSResponseInfo{}
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
	val_dapsresponseindicator, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Dapsresponseindicator"})
	if err != nil {
		return runtime.WrapDecodePath(err, "Dapsresponseindicator")
	}
	v.Dapsresponseindicator = val_dapsresponseindicator
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.DAPSResponseInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.DAPSResponseInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeDAPSResponseInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DLCPSecurityInformation to APER format.
func (v *DLCPSecurityInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DLCPSecurityInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAligned(bb, v.DlNASMAC.Bytes, v.DlNASMAC.BitLength, 16, 16, true); err != nil {
		return fmt.Errorf("encoding dl-NAS-MAC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DLCPSecurityInformation from APER format.
func (v *DLCPSecurityInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DLCPSecurityInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DLCPSecurityInformation")
	}
	bb.EnterComponent("DLCPSecurityInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCPSecurityInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "DLCPSecurityInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "DLCPSecurityInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *DLCPSecurityInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCPSecurityInformation{}
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
	bsBytes_dlnasmac, bsBitLen_dlnasmac, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "DlNASMAC")
	}
	v.DlNASMAC = runtime.BitString{Bytes: bsBytes_dlnasmac, BitLength: bsBitLen_dlnasmac}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.DLCPSecurityInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.DLCPSecurityInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DLCOUNTPDCPSNlength to APER format.
func (v *DLCOUNTPDCPSNlength) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "DLCOUNTPDCPSNlength:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "DLCOUNTPDCPSNlength:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "DLCOUNTPDCPSNlength:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "DLCOUNTPDCPSNlength:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		if v.DLCOUNTValuePDCPSNlength12 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength12 is nil")
		}
		if err := s16.BridgeCOUNTvalueMethodMarshalAPERTo(v.DLCOUNTValuePDCPSNlength12, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength12: %w", err)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		if v.DLCOUNTValuePDCPSNlength15 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength15 is nil")
		}
		if err := s16.BridgeCOUNTValueExtendedMethodMarshalAPERTo(v.DLCOUNTValuePDCPSNlength15, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength15: %w", err)
		}
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		if v.DLCOUNTValuePDCPSNlength18 == nil {
			return fmt.Errorf("choice alternative dLCOUNTValuePDCP-SNlength18 is nil")
		}
		if err := s16.BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERTo(v.DLCOUNTValuePDCPSNlength18, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding dLCOUNTValuePDCP-SNlength18: %w", err)
		}
	default:
		return fmt.Errorf("unknown DLCOUNTPDCPSNlength choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes DLCOUNTPDCPSNlength from APER format.
func (v *DLCOUNTPDCPSNlength) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DLCOUNTPDCPSNlength) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	bb.EnterComponent("DLCOUNTPDCPSNlength")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	padding, err := aper.CaptureFinalBits(bb, "DLCOUNTPDCPSNlength")
	if err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTPDCPSNlength")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *DLCOUNTPDCPSNlength) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCOUNTPDCPSNlength{}
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
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12:
		toleranceMark_dlcountvaluepdcpsnlength12 := bb.EnterComponent("DLCOUNTValuePDCPSNlength12")
		var dec_dlcountvaluepdcpsnlength12 s16.COUNTvalue
		if err := s16.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&dec_dlcountvaluepdcpsnlength12, bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength12")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength12); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength12 = &dec_dlcountvaluepdcpsnlength12
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength12)
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15:
		toleranceMark_dlcountvaluepdcpsnlength15 := bb.EnterComponent("DLCOUNTValuePDCPSNlength15")
		var dec_dlcountvaluepdcpsnlength15 s16.COUNTValueExtended
		if err := s16.BridgeCOUNTValueExtendedMethodUnmarshalAPERFrom(&dec_dlcountvaluepdcpsnlength15, bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength15")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength15); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength15 = &dec_dlcountvaluepdcpsnlength15
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength15)
	case s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18:
		toleranceMark_dlcountvaluepdcpsnlength18 := bb.EnterComponent("DLCOUNTValuePDCPSNlength18")
		var dec_dlcountvaluepdcpsnlength18 s16.COUNTvaluePDCPSNlength18
		if err := s16.BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERFrom(&dec_dlcountvaluepdcpsnlength18, bb); err != nil {
			return runtime.WrapDecodePath(err, "DLCOUNTValuePDCPSNlength18")
		}
		if err := aper.ChargeValue(bb, dec_dlcountvaluepdcpsnlength18); err != nil {
			return err
		}
		v.DLCOUNTValuePDCPSNlength18 = &dec_dlcountvaluepdcpsnlength18
		bb.LeaveComponent(toleranceMark_dlcountvaluepdcpsnlength18)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes DLDiscarding to APER format.
func (v *DLDiscarding) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *DLDiscarding) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "DLDiscarding:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "DLDiscarding:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "DLDiscarding:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "DLDiscarding:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12:
		if v.DiscardDLCOUNTValuePDCPSNlength12 == nil {
			return fmt.Errorf("choice alternative discardDLCOUNTValuePDCP-SNlength12 is nil")
		}
		if err := s16.BridgeCOUNTvalueMethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength12, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding discardDLCOUNTValuePDCP-SNlength12: %w", err)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		if v.DiscardDLCOUNTValuePDCPSNlength15 == nil {
			return fmt.Errorf("choice alternative discardDLCOUNTValuePDCP-SNlength15 is nil")
		}
		if err := s16.BridgeCOUNTValueExtendedMethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength15, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding discardDLCOUNTValuePDCP-SNlength15: %w", err)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		if v.DiscardDLCOUNTValuePDCPSNlength18 == nil {
			return fmt.Errorf("choice alternative discardDLCOUNTValuePDCP-SNlength18 is nil")
		}
		if err := s16.BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength18, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding discardDLCOUNTValuePDCP-SNlength18: %w", err)
		}
	default:
		return fmt.Errorf("unknown DLDiscarding choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes DLDiscarding from APER format.
func (v *DLDiscarding) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DLDiscarding) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DLDiscarding")
	}
	bb.EnterComponent("DLDiscarding")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLDiscarding")
	}
	padding, err := aper.CaptureFinalBits(bb, "DLDiscarding")
	if err != nil {
		return runtime.WrapDecodePath(err, "DLDiscarding")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *DLDiscarding) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLDiscarding{}
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
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12:
		toleranceMark_discarddlcountvaluepdcpsnlength12 := bb.EnterComponent("DiscardDLCOUNTValuePDCPSNlength12")
		var dec_discarddlcountvaluepdcpsnlength12 s16.COUNTvalue
		if err := s16.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength12, bb); err != nil {
			return runtime.WrapDecodePath(err, "DiscardDLCOUNTValuePDCPSNlength12")
		}
		if err := aper.ChargeValue(bb, dec_discarddlcountvaluepdcpsnlength12); err != nil {
			return err
		}
		v.DiscardDLCOUNTValuePDCPSNlength12 = &dec_discarddlcountvaluepdcpsnlength12
		bb.LeaveComponent(toleranceMark_discarddlcountvaluepdcpsnlength12)
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		toleranceMark_discarddlcountvaluepdcpsnlength15 := bb.EnterComponent("DiscardDLCOUNTValuePDCPSNlength15")
		var dec_discarddlcountvaluepdcpsnlength15 s16.COUNTValueExtended
		if err := s16.BridgeCOUNTValueExtendedMethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength15, bb); err != nil {
			return runtime.WrapDecodePath(err, "DiscardDLCOUNTValuePDCPSNlength15")
		}
		if err := aper.ChargeValue(bb, dec_discarddlcountvaluepdcpsnlength15); err != nil {
			return err
		}
		v.DiscardDLCOUNTValuePDCPSNlength15 = &dec_discarddlcountvaluepdcpsnlength15
		bb.LeaveComponent(toleranceMark_discarddlcountvaluepdcpsnlength15)
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		toleranceMark_discarddlcountvaluepdcpsnlength18 := bb.EnterComponent("DiscardDLCOUNTValuePDCPSNlength18")
		var dec_discarddlcountvaluepdcpsnlength18 s16.COUNTvaluePDCPSNlength18
		if err := s16.BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength18, bb); err != nil {
			return runtime.WrapDecodePath(err, "DiscardDLCOUNTValuePDCPSNlength18")
		}
		if err := aper.ChargeValue(bb, dec_discarddlcountvaluepdcpsnlength18); err != nil {
			return err
		}
		v.DiscardDLCOUNTValuePDCPSNlength18 = &dec_discarddlcountvaluepdcpsnlength18
		bb.LeaveComponent(toleranceMark_discarddlcountvaluepdcpsnlength18)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToDLDiscardingItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToDLDiscardingItem) WithoutReplay() BearersSubjectToDLDiscardingItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToDLDiscardingItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToEarlyStatusTransferItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToEarlyStatusTransferItem) WithoutReplay() BearersSubjectToEarlyStatusTransferItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToEarlyStatusTransferItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CSGIdListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGIdListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGIdListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGIdListItem) WithoutReplay() CSGIdListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGIdListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cause) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "Cause", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Cause", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cause) WithoutReplay() Cause {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Cause
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Cdma2000OneXSRVCCInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "Cdma2000OneXSRVCCInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Cdma2000OneXSRVCCInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Cdma2000OneXSRVCCInfo) WithoutReplay() Cdma2000OneXSRVCCInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Cdma2000OneXSRVCCInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellType) WithoutReplay() CellType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellType
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CriticalityDiagnosticsIEItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEItem) WithoutReplay() CriticalityDiagnosticsIEItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CriticalityDiagnosticsIEItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSRequestInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSRequestInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSRequestInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSRequestInfo) WithoutReplay() DAPSRequestInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSRequestInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSResponseInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSResponseInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSResponseInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSResponseInfo) WithoutReplay() DAPSResponseInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSResponseInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSResponseInfoItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSResponseInfoItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSResponseInfoItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSResponseInfoItem) WithoutReplay() DAPSResponseInfoItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSResponseInfoItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DLCOUNTPDCPSNlength) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DLCOUNTPDCPSNlength", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DLCOUNTPDCPSNlength", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DLCOUNTPDCPSNlength) WithoutReplay() DLCOUNTPDCPSNlength {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DLCOUNTPDCPSNlength
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DLCPSecurityInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DLCPSecurityInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DLCPSecurityInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DLCPSecurityInformation) WithoutReplay() DLCPSecurityInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DLCPSecurityInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DLDiscarding) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DLDiscarding", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DLDiscarding", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DLDiscarding) WithoutReplay() DLDiscarding {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DLDiscarding
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *BearersSubjectToDLDiscardingItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BearersSubjectToDLDiscardingItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToDLDiscardingItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToDLDiscardingItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BearersSubjectToDLDiscardingItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToDLDiscardingItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToDLDiscardingItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *BearersSubjectToEarlyStatusTransferItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BearersSubjectToEarlyStatusTransferItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BearersSubjectToEarlyStatusTransferItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CSGIdListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CSGIdListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CSGIdListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGIdListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *Cdma2000OneXSRVCCInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Cdma2000OneXSRVCCInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Cdma2000OneXSRVCCInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Cdma2000OneXSRVCCInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellType) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellType) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellType) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellType.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CriticalityDiagnosticsIEItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CriticalityDiagnosticsIEItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CriticalityDiagnosticsIEItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CriticalityDiagnosticsIEItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSRequestInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSRequestInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSRequestInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSRequestInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSResponseInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSResponseInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSResponseInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DAPSResponseInfoItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DAPSResponseInfoItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DAPSResponseInfoItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DAPSResponseInfoItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DLCPSecurityInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DLCPSecurityInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DLCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DLCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DLCPSecurityInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DLCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DLCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToDLDiscardingItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToDLDiscardingItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToDLDiscardingItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToDLDiscardingItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingItem")
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingItem")
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingItem(v, &s)
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
func (v *BearersSubjectToDLDiscardingItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToDLDiscardingItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BearersSubjectToEarlyStatusTransferItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToEarlyStatusTransferItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v, &s)
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
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToEarlyStatusTransferItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CSGIdListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGIdListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGIdListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGIdListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGIdListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGIdListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGIdListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGIdListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGIdListItem")
}
func (v *CSGIdListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGIdListItem")
}
func (v *CSGIdListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGIdListItem(v, &s)
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
func (v *CSGIdListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGIdListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Cause) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Cause")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Cause) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCause(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Cause")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Cause")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Cause) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Cause")
}
func (v *Cause) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCause(v, &s)
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
func (v *Cause) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Cause) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Cdma2000OneXSRVCCInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Cdma2000OneXSRVCCInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCdma2000OneXSRVCCInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Cdma2000OneXSRVCCInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCdma2000OneXSRVCCInfo(v, &s)
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
func (v *Cdma2000OneXSRVCCInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Cdma2000OneXSRVCCInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellType")
}
func (v *CellType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellType")
}
func (v *CellType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellType(v, &s)
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
func (v *CellType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CriticalityDiagnosticsIEItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCriticalityDiagnosticsIEItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CriticalityDiagnosticsIEItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCriticalityDiagnosticsIEItem(v, &s)
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
func (v *CriticalityDiagnosticsIEItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CriticalityDiagnosticsIEItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSRequestInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSRequestInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSRequestInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSRequestInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSRequestInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSRequestInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSRequestInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSRequestInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSRequestInfo")
}
func (v *DAPSRequestInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSRequestInfo")
}
func (v *DAPSRequestInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSRequestInfo(v, &s)
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
func (v *DAPSRequestInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSRequestInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSResponseInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSResponseInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSResponseInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSResponseInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSResponseInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSResponseInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSResponseInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSResponseInfo")
}
func (v *DAPSResponseInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSResponseInfo")
}
func (v *DAPSResponseInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSResponseInfo(v, &s)
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
func (v *DAPSResponseInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSResponseInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DAPSResponseInfoItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSResponseInfoItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSResponseInfoItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSResponseInfoItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSResponseInfoItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSResponseInfoItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSResponseInfoItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSResponseInfoItem")
}
func (v *DAPSResponseInfoItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSResponseInfoItem")
}
func (v *DAPSResponseInfoItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSResponseInfoItem(v, &s)
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
func (v *DAPSResponseInfoItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSResponseInfoItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DLCOUNTPDCPSNlength) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DLCOUNTPDCPSNlength")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DLCOUNTPDCPSNlength) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DLCOUNTPDCPSNlength")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDLCOUNTPDCPSNlength(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DLCOUNTPDCPSNlength")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
}
func (v *DLCOUNTPDCPSNlength) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DLCOUNTPDCPSNlength")
}
func (v *DLCOUNTPDCPSNlength) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDLCOUNTPDCPSNlength(v, &s)
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
func (v *DLCOUNTPDCPSNlength) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DLCOUNTPDCPSNlength) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DLCPSecurityInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DLCPSecurityInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DLCPSecurityInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DLCPSecurityInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDLCPSecurityInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DLCPSecurityInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DLCPSecurityInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DLCPSecurityInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DLCPSecurityInformation")
}
func (v *DLCPSecurityInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DLCPSecurityInformation")
}
func (v *DLCPSecurityInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDLCPSecurityInformation(v, &s)
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
func (v *DLCPSecurityInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DLCPSecurityInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DLDiscarding) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DLDiscarding")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DLDiscarding) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DLDiscarding")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDLDiscarding(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DLDiscarding")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DLDiscarding")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DLDiscarding) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DLDiscarding")
}
func (v *DLDiscarding) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DLDiscarding")
}
func (v *DLDiscarding) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDLDiscarding(v, &s)
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
func (v *DLDiscarding) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DLDiscarding) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BearersSubjectToDLDiscardingItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToDLDiscardingItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToDLDiscardingItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToDLDiscardingItem{}
		return report, aper.OperationError(err, "BearersSubjectToDLDiscardingItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToDLDiscardingItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToEarlyStatusTransferItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToEarlyStatusTransferItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToEarlyStatusTransferItem{}
		return report, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToEarlyStatusTransferItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CSGIdListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGIdListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGIdListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGIdListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGIdListItem{}
		return report, aper.OperationError(err, "CSGIdListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGIdListItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *Cause) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Cause")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Cause
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCause(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Cause{}
		return report, aper.OperationError(err, "Cause")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Cause")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *Cdma2000OneXSRVCCInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Cdma2000OneXSRVCCInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Cdma2000OneXSRVCCInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCdma2000OneXSRVCCInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Cdma2000OneXSRVCCInfo{}
		return report, aper.OperationError(err, "Cdma2000OneXSRVCCInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Cdma2000OneXSRVCCInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellType{}
		return report, aper.OperationError(err, "CellType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellType")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CriticalityDiagnosticsIEItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CriticalityDiagnosticsIEItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCriticalityDiagnosticsIEItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEItem{}
		return report, aper.OperationError(err, "CriticalityDiagnosticsIEItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnosticsIEItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSRequestInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSRequestInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSRequestInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSRequestInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSRequestInfo{}
		return report, aper.OperationError(err, "DAPSRequestInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSRequestInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSResponseInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSResponseInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSResponseInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSResponseInfo{}
		return report, aper.OperationError(err, "DAPSResponseInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSResponseInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSResponseInfoItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSResponseInfoItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSResponseInfoItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSResponseInfoItem{}
		return report, aper.OperationError(err, "DAPSResponseInfoItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSResponseInfoItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DLCOUNTPDCPSNlength) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DLCOUNTPDCPSNlength")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DLCOUNTPDCPSNlength
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDLCOUNTPDCPSNlength(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DLCOUNTPDCPSNlength{}
		return report, aper.OperationError(err, "DLCOUNTPDCPSNlength")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DLCOUNTPDCPSNlength")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DLCPSecurityInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DLCPSecurityInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DLCPSecurityInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDLCPSecurityInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DLCPSecurityInformation{}
		return report, aper.OperationError(err, "DLCPSecurityInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DLCPSecurityInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DLDiscarding) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DLDiscarding")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DLDiscarding
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDLDiscarding(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DLDiscarding{}
		return report, aper.OperationError(err, "DLDiscarding")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DLDiscarding")
}

// CSGMembershipInfo represents the ASN.1 type CSGMembershipInfo (SEQUENCE).
type CSGMembershipInfo struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	CSGMembershipStatus s00.CSGMembershipStatus                 `asn1:"tag:0,context,implicit"`
	CSGId               s00.CSGId                               `asn1:"tag:1,context,implicit"`
	CellAccessMode      *s00.CellAccessMode                     `asn1:"tag:2,context,implicit,optional" json:"CellAccessMode,omitempty"`
	PLMNidentity        *s00.PLMNidentity                       `asn1:"tag:3,context,implicit,optional" json:"PLMNidentity,omitempty"`
	IEExtensions        s08.CSGMembershipInfoExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                    `asn1:"-" json:"-"`
	extCount            int64                                   `asn1:"-" json:"-"`
	extPresent          []bool                                  `asn1:"-" json:"-"`
	extData             [][]byte                                `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// MarshalAPER encodes CSGMembershipInfo to APER format.
func (v *CSGMembershipInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CSGMembershipInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.CellAccessMode != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PLMNidentity != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.CSGMembershipStatus), 2, false); err != nil {
		return fmt.Errorf("encoding cSGMembershipStatus: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.CSGId.Bytes, v.CSGId.BitLength, 27, 27, true); err != nil {
		return fmt.Errorf("encoding cSG-Id: %w", err)
	}
	if v.CellAccessMode != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CellAccessMode), 1, true); err != nil {
			return fmt.Errorf("encoding cellAccessMode: %w", err)
		}
	}
	if v.PLMNidentity != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.PLMNidentity), 3, 3, true); err != nil {
			return fmt.Errorf("encoding pLMNidentity: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CSGMembershipInfo from APER format.
func (v *CSGMembershipInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CSGMembershipInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	bb.EnterComponent("CSGMembershipInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGMembershipInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipInfo")
	}
	v.perPadding = padding
	return nil
}
func (v *CSGMembershipInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CSGMembershipInfo{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_cellaccessmode, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_plmnidentity, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_csgmembershipstatus, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGMembershipStatus")
	}
	v.CSGMembershipStatus = s00.CSGMembershipStatus(val_csgmembershipstatus)
	bsBytes_csgid, bsBitLen_csgid, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGId")
	}
	v.CSGId = runtime.BitString{Bytes: bsBytes_csgid, BitLength: bsBitLen_csgid}
	if opt_cellaccessmode {
		val_cellaccessmode, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellAccessMode"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CellAccessMode")
		}
		tmp_cellaccessmode := s00.CellAccessMode(val_cellaccessmode)
		if err := aper.ChargeValue(bb, tmp_cellaccessmode); err != nil {
			return err
		}
		v.CellAccessMode = (*s00.CellAccessMode)(bb.OwnInt64(int64(tmp_cellaccessmode)))

	}
	if opt_plmnidentity {
		val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PLMNidentity")
		}
		tmp_plmnidentity := s00.PLMNidentity(val_plmnidentity)
		if err := aper.ChargeValue(bb, tmp_plmnidentity); err != nil {
			return err
		}
		v.PLMNidentity = &tmp_plmnidentity
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CSGMembershipInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CSGMembershipInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCSGMembershipInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *CSGMembershipInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGMembershipInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGMembershipInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGMembershipInfo) WithoutReplay() CSGMembershipInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGMembershipInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CSGMembershipInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CSGMembershipInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CSGMembershipInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CSGMembershipInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CSGMembershipInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGMembershipInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGMembershipInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGMembershipInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGMembershipInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGMembershipInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGMembershipInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGMembershipInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGMembershipInfo")
}
func (v *CSGMembershipInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGMembershipInfo")
}
func (v *CSGMembershipInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGMembershipInfo(v, &s)
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
func (v *CSGMembershipInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGMembershipInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CSGMembershipInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGMembershipInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGMembershipInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGMembershipInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGMembershipInfo{}
		return report, aper.OperationError(err, "CSGMembershipInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGMembershipInfo")
}

type CandidatePCIList = []CandidatePCI

// CandidatePCI represents the ASN.1 type CandidatePCI (SEQUENCE).
type CandidatePCI struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	PCI              int64                  `asn1:"tag:0,context,implicit"`
	EARFCN           []byte                 `asn1:"tag:1,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type CellsToActivateList = []CellsToActivateListItem

// CellsToActivateListItem represents the ASN.1 type CellsToActivateList-Item (SEQUENCE).
type CellsToActivateListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           []byte                 `asn1:"tag:0,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes CandidatePCI to APER format.
func (v *CandidatePCI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CandidatePCI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.PCI), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(503), false); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, v.EARFCN, 0, 0, false); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
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

// UnmarshalAPER decodes CandidatePCI from APER format.
func (v *CandidatePCI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CandidatePCI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	bb.EnterComponent("CandidatePCI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidatePCI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCI")
	}
	v.perPadding = padding
	return nil
}
func (v *CandidatePCI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CandidatePCI{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(503), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
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

// MarshalAPER encodes CellsToActivateListItem to APER format.
func (v *CellsToActivateListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellsToActivateListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes CellsToActivateListItem from APER format.
func (v *CellsToActivateListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellsToActivateListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	bb.EnterComponent("CellsToActivateListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellsToActivateListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateListItem")
	}
	v.perPadding = padding
	return nil
}
func (v *CellsToActivateListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellsToActivateListItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
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
func (v *CandidatePCI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidatePCI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidatePCI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidatePCI) WithoutReplay() CandidatePCI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidatePCI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellsToActivateListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellsToActivateListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellsToActivateListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellsToActivateListItem) WithoutReplay() CellsToActivateListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellsToActivateListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CandidatePCI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CandidatePCI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CandidatePCI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellsToActivateListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellsToActivateListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellsToActivateListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellsToActivateListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CandidatePCI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidatePCI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidatePCI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidatePCI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidatePCI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidatePCI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidatePCI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidatePCI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidatePCI")
}
func (v *CandidatePCI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidatePCI")
}
func (v *CandidatePCI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidatePCI(v, &s)
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
func (v *CandidatePCI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidatePCI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellsToActivateListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellsToActivateListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellsToActivateListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellsToActivateListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellsToActivateListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellsToActivateListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellsToActivateListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellsToActivateListItem")
}
func (v *CellsToActivateListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellsToActivateListItem")
}
func (v *CellsToActivateListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellsToActivateListItem(v, &s)
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
func (v *CellsToActivateListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellsToActivateListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CandidatePCI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidatePCI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidatePCI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidatePCI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidatePCI{}
		return report, aper.OperationError(err, "CandidatePCI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidatePCI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellsToActivateListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellsToActivateListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellsToActivateListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellsToActivateListItem{}
		return report, aper.OperationError(err, "CellsToActivateListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellsToActivateListItem")
}

type BearersSubjectToDLDiscardingItemIEValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowBearersSubjectToDLDiscardingItem *BearersSubjectToDLDiscardingItem
}

func (v BearersSubjectToDLDiscardingItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(351):
		return v.rowBearersSubjectToDLDiscardingItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToDLDiscardingItemIEValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToDLDiscardingItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToDLDiscardingItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-ItemIEs"}}
}
func (BearersSubjectToDLDiscardingItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(351):
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

// AsBearersSubjectToDLDiscardingItem returns the selected BearersSubjectToDLDiscardingItem value of BearersSubjectToDLDiscardingItemIEValue and reports whether that alternative is active.
func (v *BearersSubjectToDLDiscardingItemIEValue) AsBearersSubjectToDLDiscardingItem() (*BearersSubjectToDLDiscardingItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(351) || v.rowBearersSubjectToDLDiscardingItem == nil {
		return nil, false
	}
	return v.rowBearersSubjectToDLDiscardingItem, true
}
func (v BearersSubjectToDLDiscardingItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToDLDiscardingItemIEValue, error) {
	out := BearersSubjectToDLDiscardingItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(351):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BearersSubjectToDLDiscardingItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToDLDiscardingItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BearersSubjectToDLDiscardingItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBearersSubjectToDLDiscardingItem = &value
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
func (v BearersSubjectToDLDiscardingItemIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToDLDiscardingItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(351):
		if v.rowBearersSubjectToDLDiscardingItem == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToDLDiscarding-ItemIEs.id-Bearers-SubjectToDLDiscarding-Item:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBearersSubjectToDLDiscardingItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToDLDiscardingItemIEValue:", v.id)
	}
}

type BearersSubjectToEarlyStatusTransferItemIEValue struct {
	id                                         s00.ProtocolIEID
	received                                   aper.WireSpan
	replay                                     aper.Snapshot
	opaque                                     aper.OpaqueOpenType
	isOpaque                                   bool
	rowBearersSubjectToEarlyStatusTransferItem *BearersSubjectToEarlyStatusTransferItem
}

func (v BearersSubjectToEarlyStatusTransferItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(322):
		return v.rowBearersSubjectToEarlyStatusTransferItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToEarlyStatusTransferItemIEValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToEarlyStatusTransferItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToEarlyStatusTransferItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-ItemIEs"}}
}
func (BearersSubjectToEarlyStatusTransferItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(322):
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

// AsBearersSubjectToEarlyStatusTransferItem returns the selected BearersSubjectToEarlyStatusTransferItem value of BearersSubjectToEarlyStatusTransferItemIEValue and reports whether that alternative is active.
func (v *BearersSubjectToEarlyStatusTransferItemIEValue) AsBearersSubjectToEarlyStatusTransferItem() (*BearersSubjectToEarlyStatusTransferItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(322) || v.rowBearersSubjectToEarlyStatusTransferItem == nil {
		return nil, false
	}
	return v.rowBearersSubjectToEarlyStatusTransferItem, true
}
func (v BearersSubjectToEarlyStatusTransferItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToEarlyStatusTransferItemIEValue, error) {
	out := BearersSubjectToEarlyStatusTransferItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(322):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BearersSubjectToEarlyStatusTransferItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToEarlyStatusTransferItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BearersSubjectToEarlyStatusTransferItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBearersSubjectToEarlyStatusTransferItem = &value
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
func (v BearersSubjectToEarlyStatusTransferItemIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToEarlyStatusTransferItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(322):
		if v.rowBearersSubjectToEarlyStatusTransferItem == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToEarlyStatusTransfer-ItemIEs.id-Bearers-SubjectToEarlyStatusTransfer-Item:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBearersSubjectToEarlyStatusTransferItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToEarlyStatusTransferItemIEValue:", v.id)
	}
}

type DAPSResponseInfoListIEValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowDAPSResponseInfoItem *DAPSResponseInfoItem
}

func (v DAPSResponseInfoListIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(319):
		return v.rowDAPSResponseInfoItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of DAPSResponseInfoListIEValue and reports whether the opaque alternative is selected.
func (v *DAPSResponseInfoListIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DAPSResponseInfoListIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs"}}
}
func (DAPSResponseInfoListIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(319):
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

// AsDAPSResponseInfoItem returns the selected DAPSResponseInfoItem value of DAPSResponseInfoListIEValue and reports whether that alternative is active.
func (v *DAPSResponseInfoListIEValue) AsDAPSResponseInfoItem() (*DAPSResponseInfoItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(319) || v.rowDAPSResponseInfoItem == nil {
		return nil, false
	}
	return v.rowDAPSResponseInfoItem, true
}
func (v DAPSResponseInfoListIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DAPSResponseInfoListIEValue, error) {
	out := DAPSResponseInfoListIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(319):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value DAPSResponseInfoItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "DAPSResponseInfoItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "DAPSResponseInfoItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowDAPSResponseInfoItem = &value
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
func (v DAPSResponseInfoListIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v DAPSResponseInfoListIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(319):
		if v.rowDAPSResponseInfoItem == nil {
			return nil, fmt.Errorf("%s missing value", "DAPSResponseInfoListIEs.id-DAPSResponseInfoItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowDAPSResponseInfoItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DAPSResponseInfoListIEValue:", v.id)
	}
}

type BearersSubjectToDLDiscardingItemIETable struct{}

func BearersSubjectToDLDiscardingItemIEs() BearersSubjectToDLDiscardingItemIETable {
	return BearersSubjectToDLDiscardingItemIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToDLDiscardingItemIETable.
func (BearersSubjectToDLDiscardingItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-ItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToDLDiscardingItemIETable.
func (BearersSubjectToDLDiscardingItemIETable) Table() s00.BearersSubjectToDLDiscardingItemIEValueIETable {
	return func() s00.BearersSubjectToDLDiscardingItemIEValueIETable {
		sealed := s00.BearersSubjectToDLDiscardingItemIEValueIETable{}
		*s00.BridgeBearersSubjectToDLDiscardingItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToDLDiscardingItemIETable) infoBearersSubjectToDLDiscardingItem() s00.FieldInfo {
	return s00.FieldInfo{Table: BearersSubjectToDLDiscardingItemIEs().ID(), ID: s00.ProtocolIEID(351), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-Item"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-ItemIEs", Row: "id-Bearers-SubjectToDLDiscarding-Item"}}}
}

// BearersSubjectToDLDiscardingItem returns the typed binding for the BearersSubjectToDLDiscardingItem row of BearersSubjectToDLDiscardingItemIETable.
func (t BearersSubjectToDLDiscardingItemIETable) BearersSubjectToDLDiscardingItem() BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding {
	return BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding{info: t.infoBearersSubjectToDLDiscardingItem(), codec: BearersSubjectToDLDiscardingItemValueCodec{path: "BearersSubjectToDLDiscardingItem",
		decode: func(data []byte, options aper.DecodeState) (BearersSubjectToDLDiscardingItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BearersSubjectToDLDiscardingItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToDLDiscardingItem")
			var zero BearersSubjectToDLDiscardingItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(351), raw)
			if err != nil {
				var empty BearersSubjectToDLDiscardingItem
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItem")
			}
			value, ok := decoded.AsBearersSubjectToDLDiscardingItem()
			if !ok {
				var empty BearersSubjectToDLDiscardingItem
				return empty, fmt.Errorf("binding Bearers-SubjectToDLDiscarding-ItemIEs.id-Bearers-SubjectToDLDiscarding-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value BearersSubjectToDLDiscardingItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToDLDiscardingItemIEValue{id: s00.ProtocolIEID(351), rowBearersSubjectToDLDiscardingItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BearersSubjectToDLDiscardingItem, options aper.DecodeState) (BearersSubjectToDLDiscardingItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBearersSubjectToDLDiscardingItem(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v BearersSubjectToDLDiscardingItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBearersSubjectToDLDiscardingItem(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToDLDiscardingItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BearersSubjectToDLDiscardingItem) BearersSubjectToDLDiscardingItemIEValue {
		return BearersSubjectToDLDiscardingItemIEValue{id: s00.ProtocolIEID(351), rowBearersSubjectToDLDiscardingItem: &value}
	}, get: func(value *BearersSubjectToDLDiscardingItemIEValue) (*BearersSubjectToDLDiscardingItem, bool) {
		return value.AsBearersSubjectToDLDiscardingItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToDLDiscardingItemIETable.
func (t BearersSubjectToDLDiscardingItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (BearersSubjectToDLDiscardingItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(351):
		return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-Bearers-SubjectToDLDiscarding-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToDLDiscardingItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToDLDiscardingItemIEField{Id: id, Criticality: criticality, Value: BearersSubjectToDLDiscardingItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type BearersSubjectToEarlyStatusTransferItemIETable struct{}

func BearersSubjectToEarlyStatusTransferItemIEs() BearersSubjectToEarlyStatusTransferItemIETable {
	return BearersSubjectToEarlyStatusTransferItemIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToEarlyStatusTransferItemIETable.
func (BearersSubjectToEarlyStatusTransferItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-ItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToEarlyStatusTransferItemIETable.
func (BearersSubjectToEarlyStatusTransferItemIETable) Table() s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable {
	return func() s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable {
		sealed := s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable{}
		*s00.BridgeBearersSubjectToEarlyStatusTransferItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToEarlyStatusTransferItemIETable) infoBearersSubjectToEarlyStatusTransferItem() s00.FieldInfo {
	return s00.FieldInfo{Table: BearersSubjectToEarlyStatusTransferItemIEs().ID(), ID: s00.ProtocolIEID(322), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-Item"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-ItemIEs", Row: "id-Bearers-SubjectToEarlyStatusTransfer-Item"}}}
}

// BearersSubjectToEarlyStatusTransferItem returns the typed binding for the BearersSubjectToEarlyStatusTransferItem row of BearersSubjectToEarlyStatusTransferItemIETable.
func (t BearersSubjectToEarlyStatusTransferItemIETable) BearersSubjectToEarlyStatusTransferItem() BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding {
	return BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding{info: t.infoBearersSubjectToEarlyStatusTransferItem(), codec: BearersSubjectToEarlyStatusTransferItemValueCodec{path: "BearersSubjectToEarlyStatusTransferItem",
		decode: func(data []byte, options aper.DecodeState) (BearersSubjectToEarlyStatusTransferItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BearersSubjectToEarlyStatusTransferItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToEarlyStatusTransferItem")
			var zero BearersSubjectToEarlyStatusTransferItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(322), raw)
			if err != nil {
				var empty BearersSubjectToEarlyStatusTransferItem
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
			}
			value, ok := decoded.AsBearersSubjectToEarlyStatusTransferItem()
			if !ok {
				var empty BearersSubjectToEarlyStatusTransferItem
				return empty, fmt.Errorf("binding Bearers-SubjectToEarlyStatusTransfer-ItemIEs.id-Bearers-SubjectToEarlyStatusTransfer-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value BearersSubjectToEarlyStatusTransferItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToEarlyStatusTransferItemIEValue{id: s00.ProtocolIEID(322), rowBearersSubjectToEarlyStatusTransferItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BearersSubjectToEarlyStatusTransferItem, options aper.DecodeState) (BearersSubjectToEarlyStatusTransferItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v BearersSubjectToEarlyStatusTransferItem, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToEarlyStatusTransferItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BearersSubjectToEarlyStatusTransferItem) BearersSubjectToEarlyStatusTransferItemIEValue {
		return BearersSubjectToEarlyStatusTransferItemIEValue{id: s00.ProtocolIEID(322), rowBearersSubjectToEarlyStatusTransferItem: &value}
	}, get: func(value *BearersSubjectToEarlyStatusTransferItemIEValue) (*BearersSubjectToEarlyStatusTransferItem, bool) {
		return value.AsBearersSubjectToEarlyStatusTransferItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToEarlyStatusTransferItemIETable.
func (t BearersSubjectToEarlyStatusTransferItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (BearersSubjectToEarlyStatusTransferItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(322):
		return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-Bearers-SubjectToEarlyStatusTransfer-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToEarlyStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToEarlyStatusTransferItemIEField{Id: id, Criticality: criticality, Value: BearersSubjectToEarlyStatusTransferItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type BearersSubjectToStatusTransferItemExtIETable struct{}

func BearersSubjectToStatusTransferItemExtIEs() BearersSubjectToStatusTransferItemExtIETable {
	return BearersSubjectToStatusTransferItemExtIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToStatusTransferItemExtIETable.
func (BearersSubjectToStatusTransferItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToStatusTransferItemExtIETable.
func (BearersSubjectToStatusTransferItemExtIETable) Table() s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable {
	return func() s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable {
		sealed := s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable{}
		*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemExtIETable) infoULCOUNTValueExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(179), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ULCOUNTValueExtended"}}}
}

// ULCOUNTValueExtended returns the typed binding for the ULCOUNTValueExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ULCOUNTValueExtended() s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
	return func() s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
		sealed := s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding{}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInfo(&sealed) = t.infoULCOUNTValueExtended()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldCodec(&sealed) = func() s16.COUNTValueExtendedValueCodec {
			sealed := s16.COUNTValueExtendedValueCodec{}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldPath(&sealed) = "COUNTValueExtended"
			*s16.BridgeCOUNTValueExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.COUNTValueExtended, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s16.COUNTValueExtended
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("COUNTValueExtended")
				var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
				decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(179), raw)
				if err != nil {
					var empty s16.COUNTValueExtended
					return empty, runtime.WrapDecodePath(err, "COUNTValueExtended")
				}
				value, ok := decoded.AsULCOUNTValueExtended()
				if !ok {
					var empty s16.COUNTValueExtended
					return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValueExtended: no selected value")
				}
				return *value, nil
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldEncode(&sealed) = func(value s16.COUNTValueExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
					sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(179)
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldCapture(&sealed) = func(v s16.COUNTValueExtended, options aper.DecodeState) (s16.COUNTValueExtended, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s16.BridgeCaptureS1APCOUNTValueExtended(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,

					root
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldCompare(&sealed) = func(v s16.COUNTValueExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s16.BridgeCompareS1APCOUNTValueExtended(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTValueExtended"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInject(&sealed) = func(value s16.COUNTValueExtended) s16.BearersSubjectToStatusTransferItemExtIEsValue {
			return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(179)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValueExtended(&sealed) = &value
				return sealed
			}()
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldGet(&sealed) = func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s16.COUNTValueExtended, bool) {
			return value.AsULCOUNTValueExtended()
		}
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemExtIETable) infoDLCOUNTValueExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(180), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-DLCOUNTValueExtended"}}}
}

// DLCOUNTValueExtended returns the typed binding for the DLCOUNTValueExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) DLCOUNTValueExtended() s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
	return func() s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding {
		sealed := s16.BearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBinding{}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInfo(&sealed) = t.infoDLCOUNTValueExtended()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldCodec(&sealed) = func() s16.COUNTValueExtendedValueCodec {
			sealed := s16.COUNTValueExtendedValueCodec{}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldPath(&sealed) = "COUNTValueExtended"
			*s16.BridgeCOUNTValueExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.COUNTValueExtended, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s16.COUNTValueExtended
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("COUNTValueExtended")
				var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
				decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(180), raw)
				if err != nil {
					var empty s16.COUNTValueExtended
					return empty, runtime.WrapDecodePath(err, "COUNTValueExtended")
				}
				value, ok := decoded.AsDLCOUNTValueExtended()
				if !ok {
					var empty s16.COUNTValueExtended
					return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValueExtended: no selected value")
				}
				return *value, nil
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldEncode(&sealed) = func(value s16.COUNTValueExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
					sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(180)
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldCapture(&sealed) = func(v s16.COUNTValueExtended, options aper.DecodeState) (s16.COUNTValueExtended, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s16.BridgeCaptureS1APCOUNTValueExtended(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,

					root
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldCompare(&sealed) = func(v s16.COUNTValueExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s16.BridgeCompareS1APCOUNTValueExtended(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s16.BridgeCOUNTValueExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTValueExtended"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldInject(&sealed) = func(value s16.COUNTValueExtended) s16.BearersSubjectToStatusTransferItemExtIEsValue {
			return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(180)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValueExtended(&sealed) = &value
				return sealed
			}()
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsCOUNTValueExtendedExtBindingFieldGet(&sealed) = func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s16.COUNTValueExtended, bool) {
			return value.AsDLCOUNTValueExtended()
		}
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemExtIETable) infoReceiveStatusOfULPDCPSDUsExtended() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(181), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ReceiveStatusOfULPDCPSDUsExtended"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ReceiveStatusOfULPDCPSDUsExtended"}}}
}

// ReceiveStatusOfULPDCPSDUsExtended returns the typed binding for the ReceiveStatusOfULPDCPSDUsExtended row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ReceiveStatusOfULPDCPSDUsExtended() s16.BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding {
	return func() s16.BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding {
		sealed := s16.BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBinding{}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInfo(&sealed) = t.infoReceiveStatusOfULPDCPSDUsExtended()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldCodec(&sealed) = func() s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
			sealed := s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec{}
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldPath(&sealed) = "ReceiveStatusOfULPDCPSDUsExtended"
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ReceiveStatusOfULPDCPSDUsExtended
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ReceiveStatusOfULPDCPSDUsExtended")
				var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
				decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(181), raw)
				if err != nil {
					var empty s00.ReceiveStatusOfULPDCPSDUsExtended
					return empty, runtime.WrapDecodePath(err, "ReceiveStatusOfULPDCPSDUsExtended")
				}
				value, ok := decoded.AsReceiveStatusOfULPDCPSDUsExtended()
				if !ok {
					var empty s00.ReceiveStatusOfULPDCPSDUsExtended
					return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsExtended: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldEncode(&sealed) = func(value s00.ReceiveStatusOfULPDCPSDUsExtended, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
					sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(181)
					*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCapture(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsExtended, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsExtended(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCompare(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsExtended, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s08.BridgeCompareS1APReceiveStatusOfULPDCPSDUsExtended(
					&v,

					&s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReceiveStatusOfULPDCPSDUsExtended"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldInject(&sealed) = func(value s00.ReceiveStatusOfULPDCPSDUsExtended) s16.BearersSubjectToStatusTransferItemExtIEsValue {
			return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(181)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsExtended(&sealed) = &value
				return sealed
			}()
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsExtendedExtBindingFieldGet(&sealed) = func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsExtended, bool) {
			return value.AsReceiveStatusOfULPDCPSDUsExtended()
		}
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemExtIETable) infoULCOUNTValuePDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(217), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ULCOUNTValuePDCP-SNlength18"}}}
}

// ULCOUNTValuePDCPSNlength18 returns the typed binding for the ULCOUNTValuePDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ULCOUNTValuePDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding{info: t.infoULCOUNTValuePDCPSNlength18(), codec: COUNTvaluePDCPSNlength18ValueCodec{path: "COUNTvaluePDCPSNlength18",
		decode: func(data []byte, options aper.DecodeState) (s16.COUNTvaluePDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTvaluePDCPSNlength18")
			var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(217), raw)
			if err != nil {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
			}
			value, ok := decoded.AsULCOUNTValuePDCPSNlength18()
			if !ok {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ULCOUNTValuePDCP-SNlength18: no selected value")
			}
			return *value, nil
		},
		encode: func(value s16.COUNTvaluePDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(217)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s16.COUNTvaluePDCPSNlength18, options aper.DecodeState) (s16.COUNTvaluePDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s16.BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v s16.COUNTvaluePDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s16.BridgeCompareS1APCOUNTvaluePDCPSNlength18(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvaluePDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s16.COUNTvaluePDCPSNlength18) s16.BearersSubjectToStatusTransferItemExtIEsValue {
		return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
			sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(217)
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowULCOUNTValuePDCPSNlength18(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s16.COUNTvaluePDCPSNlength18, bool) {
		return value.AsULCOUNTValuePDCPSNlength18()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoDLCOUNTValuePDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(218), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-DLCOUNTValuePDCP-SNlength18"}}}
}

// DLCOUNTValuePDCPSNlength18 returns the typed binding for the DLCOUNTValuePDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) DLCOUNTValuePDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsCOUNTvaluePDCPSNlength18ExtBinding{info: t.infoDLCOUNTValuePDCPSNlength18(), codec: COUNTvaluePDCPSNlength18ValueCodec{path: "COUNTvaluePDCPSNlength18",
		decode: func(data []byte, options aper.DecodeState) (s16.COUNTvaluePDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("COUNTvaluePDCPSNlength18")
			var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(218), raw)
			if err != nil {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "COUNTvaluePDCPSNlength18")
			}
			value, ok := decoded.AsDLCOUNTValuePDCPSNlength18()
			if !ok {
				var empty s16.COUNTvaluePDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-DLCOUNTValuePDCP-SNlength18: no selected value")
			}
			return *value, nil
		},
		encode: func(value s16.COUNTvaluePDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(218)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s16.COUNTvaluePDCPSNlength18, options aper.DecodeState) (s16.COUNTvaluePDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s16.BridgeCaptureS1APCOUNTvaluePDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v s16.COUNTvaluePDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s16.BridgeCompareS1APCOUNTvaluePDCPSNlength18(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvaluePDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s16.COUNTvaluePDCPSNlength18) s16.BearersSubjectToStatusTransferItemExtIEsValue {
		return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
			sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(218)
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowDLCOUNTValuePDCPSNlength18(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s16.COUNTvaluePDCPSNlength18, bool) {
		return value.AsDLCOUNTValuePDCPSNlength18()
	}}
}
func (BearersSubjectToStatusTransferItemExtIETable) infoReceiveStatusOfULPDCPSDUsPDCPSNlength18() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: BearersSubjectToStatusTransferItemExtIEs().ID(), ID: s00.ProtocolExtensionID(219), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ReceiveStatusOfULPDCPSDUsPDCP-SNlength18"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemExtIEs", Row: "id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18"}}}
}

// ReceiveStatusOfULPDCPSDUsPDCPSNlength18 returns the typed binding for the ReceiveStatusOfULPDCPSDUsPDCPSNlength18 row of BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) ReceiveStatusOfULPDCPSDUsPDCPSNlength18() BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding {
	return BearersSubjectToStatusTransferItemExtIEsReceiveStatusOfULPDCPSDUsPDCPSNlength18ExtBinding{info: t.infoReceiveStatusOfULPDCPSDUsPDCPSNlength18(), codec: func() s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
		sealed := s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec{}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldPath(&sealed) = "ReceiveStatusOfULPDCPSDUsPDCPSNlength18"
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ReceiveStatusOfULPDCPSDUsPDCPSNlength18")
			var zero s16.BearersSubjectToStatusTransferItemExtIEsValue
			decoded, err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodDecode(zero, s00.ProtocolIEID(219), raw)
			if err != nil {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, runtime.WrapDecodePath(err, "ReceiveStatusOfULPDCPSDUsPDCPSNlength18")
			}
			value, ok := decoded.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18()
			if !ok {
				var empty s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemExtIEs.id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldEncode(&sealed) = func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodEncodeFresh((func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(219)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCapture(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, options aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCompare(&sealed) = func(v s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APReceiveStatusOfULPDCPSDUsPDCPSNlength18(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReceiveStatusOfULPDCPSDUsPDCPSNlength18"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18) s16.BearersSubjectToStatusTransferItemExtIEsValue {
			return func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
				sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = s00.ProtocolIEID(219)
				*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldRowReceiveStatusOfULPDCPSDUsPDCPSNlength18(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s16.BearersSubjectToStatusTransferItemExtIEsValue) (*s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool) {
			return value.AsReceiveStatusOfULPDCPSDUsPDCPSNlength18()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToStatusTransferItemExtIETable.
func (t BearersSubjectToStatusTransferItemExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (s16.BearersSubjectToStatusTransferItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(179):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ULCOUNTValueExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(180):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DLCOUNTValueExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(181):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ReceiveStatusOfULPDCPSDUsExtended requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(217):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ULCOUNTValuePDCP-SNlength18 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(218):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-DLCOUNTValuePDCP-SNlength18 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(219):
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s16.BearersSubjectToStatusTransferItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return s16.BearersSubjectToStatusTransferItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: func() s16.BearersSubjectToStatusTransferItemExtIEsValue {
			sealed := s16.BearersSubjectToStatusTransferItemExtIEsValue{}
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldId(&sealed) = id
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldOpaque(&sealed) = opaque
			*s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type DAPSResponseInfoListIETable struct{}

func DAPSResponseInfoListIEs() DAPSResponseInfoListIETable { return DAPSResponseInfoListIETable{} }

// ID returns the ASN.1 object-set identity of DAPSResponseInfoListIETable.
func (DAPSResponseInfoListIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by DAPSResponseInfoListIETable.
func (DAPSResponseInfoListIETable) Table() s00.DAPSResponseInfoListIEValueIETable {
	return func() s00.DAPSResponseInfoListIEValueIETable {
		sealed := s00.DAPSResponseInfoListIEValueIETable{}
		*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DAPSResponseInfoListIETable) infoDAPSResponseInfoItem() s00.FieldInfo {
	return s00.FieldInfo{Table: DAPSResponseInfoListIEs().ID(), ID: s00.ProtocolIEID(319), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DAPSResponseInfoListIEs", Row: "id-DAPSResponseInfoItem"}}}
}

// DAPSResponseInfoItem returns the typed binding for the DAPSResponseInfoItem row of DAPSResponseInfoListIETable.
func (t DAPSResponseInfoListIETable) DAPSResponseInfoItem() DAPSResponseInfoListDAPSResponseInfoItemIEBinding {
	return DAPSResponseInfoListDAPSResponseInfoItemIEBinding{info: t.infoDAPSResponseInfoItem(), codec: DAPSResponseInfoItemValueCodec{path: "DAPSResponseInfoItem",
		decode: func(data []byte, options aper.DecodeState) (DAPSResponseInfoItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty DAPSResponseInfoItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DAPSResponseInfoItem")
			var zero DAPSResponseInfoListIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(319), raw)
			if err != nil {
				var empty DAPSResponseInfoItem
				return empty, runtime.WrapDecodePath(err, "DAPSResponseInfoItem")
			}
			value, ok := decoded.AsDAPSResponseInfoItem()
			if !ok {
				var empty DAPSResponseInfoItem
				return empty, fmt.Errorf("binding DAPSResponseInfoListIEs.id-DAPSResponseInfoItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value DAPSResponseInfoItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DAPSResponseInfoListIEValue{id: s00.ProtocolIEID(319), rowDAPSResponseInfoItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v DAPSResponseInfoItem, options aper.DecodeState) (DAPSResponseInfoItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APDAPSResponseInfoItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v DAPSResponseInfoItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APDAPSResponseInfoItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSResponseInfoItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value DAPSResponseInfoItem) DAPSResponseInfoListIEValue {
		return DAPSResponseInfoListIEValue{id: s00.ProtocolIEID(319), rowDAPSResponseInfoItem: &value}
	}, get: func(value *DAPSResponseInfoListIEValue) (*DAPSResponseInfoItem, bool) {
		return value.AsDAPSResponseInfoItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in DAPSResponseInfoListIETable.
func (t DAPSResponseInfoListIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DAPSResponseInfoListIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(319):
		return DAPSResponseInfoListIEField{}, aper.OperationError(fmt.Errorf("known IE id-DAPSResponseInfoItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DAPSResponseInfoListIEField{}, aper.OperationError(err, "Opaque")
		}
		return DAPSResponseInfoListIEField{Id: id, Criticality: criticality, Value: DAPSResponseInfoListIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// BearersSubjectToDLDiscardingItemCodec binds the complete APER value type.
func BearersSubjectToDLDiscardingItemCodec() BearersSubjectToDLDiscardingItemValueCodec {
	return BearersSubjectToDLDiscardingItemIEs().BearersSubjectToDLDiscardingItem().Codec()
}

// BearersSubjectToEarlyStatusTransferItemCodec binds the complete APER value type.
func BearersSubjectToEarlyStatusTransferItemCodec() BearersSubjectToEarlyStatusTransferItemValueCodec {
	return BearersSubjectToEarlyStatusTransferItemIEs().BearersSubjectToEarlyStatusTransferItem().Codec()
}

// COUNTValueExtendedCodec binds the complete APER value type.
func COUNTValueExtendedCodec() s16.COUNTValueExtendedValueCodec {
	return BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValueExtended().Codec()
}

// COUNTvalueCodec binds the complete source value type.
func COUNTvalueCodec() COUNTvalueValueCodec {
	return COUNTvalueValueCodec{path: "COUNTvalue", decode: func(data []byte, options aper.DecodeState) (s16.COUNTvalue, error) {
		var value s16.COUNTvalue
		if err := s16.BridgeCOUNTvalueMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s16.COUNTvalue{}, err
		}
		*s16.BridgeCOUNTvalueFieldReceived(&value) = true
		*s16.BridgeCOUNTvalueFieldReceivedAbsolute(&value) = true
		*s16.BridgeCOUNTvalueFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s16.COUNTvalue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s16.BridgeCOUNTvalueMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s16.COUNTvalue, options aper.DecodeState) (s16.COUNTvalue, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s16.BridgeCaptureS1APCOUNTvalue(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s16.COUNTvalue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s16.BridgeCompareS1APCOUNTvalue(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:COUNTvalue"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// COUNTvaluePDCPSNlength18Codec binds the complete APER value type.
func COUNTvaluePDCPSNlength18Codec() COUNTvaluePDCPSNlength18ValueCodec {
	return BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValuePDCPSNlength18().Codec()
}

// CSGIdListItemCodec binds the complete source value type.
func CSGIdListItemCodec() CSGIdListItemValueCodec {
	return CSGIdListItemValueCodec{path: "CSGIdListItem", decode: func(data []byte, options aper.DecodeState) (CSGIdListItem, error) {
		var value CSGIdListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CSGIdListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CSGIdListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CSGIdListItem, options aper.DecodeState) (CSGIdListItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCSGIdListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CSGIdListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCSGIdListItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(),

			s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CandidatePCICodec binds the complete source value type.
func CandidatePCICodec() CandidatePCIValueCodec {
	return CandidatePCIValueCodec{path: "CandidatePCI", decode: func(data []byte, options aper.DecodeState) (CandidatePCI, error) {
		var value CandidatePCI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CandidatePCI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CandidatePCI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CandidatePCI, options aper.DecodeState) (CandidatePCI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCandidatePCI(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CandidatePCI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCandidatePCI(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidatePCI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellTypeCodec binds the complete source value type.
func CellTypeCodec() CellTypeValueCodec {
	return CellTypeValueCodec{path: "CellType", decode: func(data []byte, options aper.DecodeState) (CellType, error) {
		var value CellType
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellType{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellType, options aper.DecodeState) (CellType, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APCellType(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellType(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellType"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellsToActivateListItemCodec binds the complete source value type.
func CellsToActivateListItemCodec() CellsToActivateListItemValueCodec {
	return CellsToActivateListItemValueCodec{path: "CellsToActivateListItem", decode: func(data []byte, options aper.DecodeState) (CellsToActivateListItem, error) {
		var value CellsToActivateListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellsToActivateListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellsToActivateListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellsToActivateListItem, options aper.DecodeState) (CellsToActivateListItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellsToActivateListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false,
		)
		return v, root
	}, compare: func(v CellsToActivateListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellsToActivateListItem(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellsToActivateListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CriticalityDiagnosticsIEItemCodec binds the complete source value type.
func CriticalityDiagnosticsIEItemCodec() CriticalityDiagnosticsIEItemValueCodec {
	return CriticalityDiagnosticsIEItemValueCodec{path: "CriticalityDiagnosticsIEItem", decode: func(data []byte, options aper.DecodeState) (CriticalityDiagnosticsIEItem, error) {
		var value CriticalityDiagnosticsIEItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CriticalityDiagnosticsIEItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CriticalityDiagnosticsIEItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CriticalityDiagnosticsIEItem, options aper.DecodeState) (CriticalityDiagnosticsIEItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCriticalityDiagnosticsIEItem(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v CriticalityDiagnosticsIEItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APCriticalityDiagnosticsIEItem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DAPSResponseInfoCodec binds the complete source value type.
func DAPSResponseInfoCodec() DAPSResponseInfoValueCodec {
	return DAPSResponseInfoValueCodec{path: "DAPSResponseInfo", decode: func(data []byte, options aper.DecodeState) (DAPSResponseInfo, error) {
		var value DAPSResponseInfo
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return DAPSResponseInfo{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value DAPSResponseInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v DAPSResponseInfo, options aper.DecodeState) (DAPSResponseInfo, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APDAPSResponseInfo(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DAPSResponseInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APDAPSResponseInfo(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DAPSResponseInfo"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DAPSResponseInfoItemCodec binds the complete APER value type.
func DAPSResponseInfoItemCodec() DAPSResponseInfoItemValueCodec {
	return DAPSResponseInfoListIEs().DAPSResponseInfoItem().Codec()
}

// DLCOUNTPDCPSNlengthCodec binds the complete source value type.
func DLCOUNTPDCPSNlengthCodec() DLCOUNTPDCPSNlengthValueCodec {
	return DLCOUNTPDCPSNlengthValueCodec{path: "DLCOUNTPDCPSNlength", decode: func(data []byte, options aper.DecodeState) (DLCOUNTPDCPSNlength, error) {
		var value DLCOUNTPDCPSNlength
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return DLCOUNTPDCPSNlength{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value DLCOUNTPDCPSNlength, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v DLCOUNTPDCPSNlength, options aper.DecodeState) (DLCOUNTPDCPSNlength, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APDLCOUNTPDCPSNlength(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DLCOUNTPDCPSNlength, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APDLCOUNTPDCPSNlength(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLCOUNTPDCPSNlength"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// DLDiscardingCodec binds the complete source value type.
func DLDiscardingCodec() DLDiscardingValueCodec {
	return DLDiscardingValueCodec{path: "DLDiscarding", decode: func(data []byte, options aper.DecodeState) (DLDiscarding, error) {
		var value DLDiscarding
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return DLDiscarding{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value DLDiscarding, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v DLDiscarding, options aper.DecodeState) (DLDiscarding, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APDLDiscarding(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DLDiscarding, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APDLDiscarding(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLDiscarding"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *func(BearersSubjectToDLDiscardingItemIEContainer, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *func(BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *func(BearersSubjectToDLDiscardingItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v *BearersSubjectToDLDiscardingItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(v *BearersSubjectToDLDiscardingItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(v *BearersSubjectToDLDiscardingItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *func(BearersSubjectToDLDiscardingItemIEField, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *func(BearersSubjectToDLDiscardingItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEField, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *func(BearersSubjectToDLDiscardingItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldId(v *BearersSubjectToDLDiscardingItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldIsOpaque(v *BearersSubjectToDLDiscardingItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldOpaque(v *BearersSubjectToDLDiscardingItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldRowBearersSubjectToDLDiscardingItem(v *BearersSubjectToDLDiscardingItemIEValue) **BearersSubjectToDLDiscardingItem {
	return &v.rowBearersSubjectToDLDiscardingItem
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodCaptureSemantics(v BearersSubjectToDLDiscardingItemIEValue, a0 aper.SemanticCapture) BearersSubjectToDLDiscardingItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodCompareSemantics(v BearersSubjectToDLDiscardingItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodMatchesID(v BearersSubjectToDLDiscardingItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodRule(v BearersSubjectToDLDiscardingItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldCapture(v *BearersSubjectToDLDiscardingListValueCodec) *func(BearersSubjectToDLDiscardingList, aper.DecodeState) (BearersSubjectToDLDiscardingList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldCompare(v *BearersSubjectToDLDiscardingListValueCodec) *func(BearersSubjectToDLDiscardingList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldContext(v *BearersSubjectToDLDiscardingListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldDecode(v *BearersSubjectToDLDiscardingListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingList, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(v *BearersSubjectToDLDiscardingListValueCodec) *func(BearersSubjectToDLDiscardingList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingListValueCodecFieldPath(v *BearersSubjectToDLDiscardingListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEContainer, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEContainer, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(v *BearersSubjectToEarlyStatusTransferItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(v *BearersSubjectToEarlyStatusTransferItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEField, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEField, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldId(v *BearersSubjectToEarlyStatusTransferItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldIsOpaque(v *BearersSubjectToEarlyStatusTransferItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldOpaque(v *BearersSubjectToEarlyStatusTransferItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldRowBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItemIEValue) **BearersSubjectToEarlyStatusTransferItem {
	return &v.rowBearersSubjectToEarlyStatusTransferItem
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCaptureSemantics(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 aper.SemanticCapture) BearersSubjectToEarlyStatusTransferItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCompareSemantics(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodMatchesID(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodRule(v BearersSubjectToEarlyStatusTransferItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *func(BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferListValueCodec) *func(BearersSubjectToEarlyStatusTransferList, aper.DecodeState) (BearersSubjectToEarlyStatusTransferList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferListValueCodec) *func(BearersSubjectToEarlyStatusTransferList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToEarlyStatusTransferList, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferListValueCodec) *func(BearersSubjectToEarlyStatusTransferList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCSGIdListItemMethodMarshalAPERTo(v *CSGIdListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCSGIdListItemMethodUnmarshalAPERFrom(v *CSGIdListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGIdListValueCodecFieldCapture(v *CSGIdListValueCodec) *func(CSGIdList, aper.DecodeState) (CSGIdList, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGIdListValueCodecFieldCompare(v *CSGIdListValueCodec) *func(CSGIdList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGIdListValueCodecFieldContext(v *CSGIdListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGIdListValueCodecFieldDecode(v *CSGIdListValueCodec) *func([]byte, aper.DecodeState) (CSGIdList, error) {
	return &v.decode
}
func BridgeCSGIdListValueCodecFieldEncode(v *CSGIdListValueCodec) *func(CSGIdList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGIdListValueCodecFieldPath(v *CSGIdListValueCodec) *aper.Path { return &v.path }
func BridgeCSGMembershipInfoFieldPerPadding(v *CSGMembershipInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCSGMembershipInfoFieldReceived(v *CSGMembershipInfo) *bool { return &v.received }
func BridgeCSGMembershipInfoFieldReceivedBytes(v *CSGMembershipInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCSGMembershipInfoFieldReceivedLocation(v *CSGMembershipInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeCSGMembershipInfoMethodMarshalAPERBudget(v *CSGMembershipInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCSGMembershipInfoMethodUnmarshalAPERFrom(v *CSGMembershipInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCSGMembershipInfoValueCodecFieldCapture(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, aper.DecodeState) (CSGMembershipInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeCSGMembershipInfoValueCodecFieldCompare(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCSGMembershipInfoValueCodecFieldContext(v *CSGMembershipInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCSGMembershipInfoValueCodecFieldDecode(v *CSGMembershipInfoValueCodec) *func([]byte, aper.DecodeState) (CSGMembershipInfo, error) {
	return &v.decode
}
func BridgeCSGMembershipInfoValueCodecFieldEncode(v *CSGMembershipInfoValueCodec) *func(CSGMembershipInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCSGMembershipInfoValueCodecFieldPath(v *CSGMembershipInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeCandidatePCIFieldStream(v *CandidatePCI) *aper.WireSpan { return &v.stream }
func BridgeCandidatePCIListValueCodecFieldCapture(v *CandidatePCIListValueCodec) *func(CandidatePCIList, aper.DecodeState) (CandidatePCIList, aper.Snapshot) {
	return &v.capture
}
func BridgeCandidatePCIListValueCodecFieldCompare(v *CandidatePCIListValueCodec) *func(CandidatePCIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCandidatePCIListValueCodecFieldContext(v *CandidatePCIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCandidatePCIListValueCodecFieldDecode(v *CandidatePCIListValueCodec) *func([]byte, aper.DecodeState) (CandidatePCIList, error) {
	return &v.decode
}
func BridgeCandidatePCIListValueCodecFieldEncode(v *CandidatePCIListValueCodec) *func(CandidatePCIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCandidatePCIListValueCodecFieldPath(v *CandidatePCIListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCandidatePCIMethodMarshalAPERTo(v *CandidatePCI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCandidatePCIMethodUnmarshalAPERFrom(v *CandidatePCI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCauseFieldPerPadding(v *Cause) *aper.CompletePadding { return &v.perPadding }
func BridgeCauseFieldReceived(v *Cause) *bool                   { return &v.received }
func BridgeCauseFieldReceivedBytes(v *Cause) *aper.WireSpan     { return &v.receivedBytes }
func BridgeCauseFieldReceivedLocation(v *Cause) *aper.Location  { return &v.receivedLocation }
func BridgeCauseMethodMarshalAPERBudget(v *Cause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCauseMethodMarshalAPERTo(v *Cause, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCauseMethodUnmarshalAPERFrom(v *Cause, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCauseValueCodecFieldCapture(v *CauseValueCodec) *func(Cause, aper.DecodeState) (Cause, aper.Snapshot) {
	return &v.capture
}
func BridgeCauseValueCodecFieldCompare(v *CauseValueCodec) *func(Cause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCauseValueCodecFieldContext(v *CauseValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeCauseValueCodecFieldDecode(v *CauseValueCodec) *func([]byte, aper.DecodeState) (Cause, error) {
	return &v.decode
}
func BridgeCauseValueCodecFieldEncode(v *CauseValueCodec) *func(Cause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseValueCodecFieldPath(v *CauseValueCodec) *aper.Path { return &v.path }
func BridgeCdma2000OneXSRVCCInfoFieldPerPadding(v *Cdma2000OneXSRVCCInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCdma2000OneXSRVCCInfoFieldReceived(v *Cdma2000OneXSRVCCInfo) *bool { return &v.received }
func BridgeCdma2000OneXSRVCCInfoFieldReceivedBytes(v *Cdma2000OneXSRVCCInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCdma2000OneXSRVCCInfoFieldReceivedLocation(v *Cdma2000OneXSRVCCInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeCdma2000OneXSRVCCInfoMethodMarshalAPERBudget(v *Cdma2000OneXSRVCCInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCdma2000OneXSRVCCInfoMethodUnmarshalAPERFrom(v *Cdma2000OneXSRVCCInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldCapture(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, aper.DecodeState) (Cdma2000OneXSRVCCInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldCompare(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldContext(v *Cdma2000OneXSRVCCInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldDecode(v *Cdma2000OneXSRVCCInfoValueCodec) *func([]byte, aper.DecodeState) (Cdma2000OneXSRVCCInfo, error) {
	return &v.decode
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(v *Cdma2000OneXSRVCCInfoValueCodec) *func(Cdma2000OneXSRVCCInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCdma2000OneXSRVCCInfoValueCodecFieldPath(v *Cdma2000OneXSRVCCInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellTypeMethodMarshalAPERTo(v *CellType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellTypeMethodUnmarshalAPERFrom(v *CellType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellsToActivateListItemMethodMarshalAPERTo(v *CellsToActivateListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellsToActivateListItemMethodUnmarshalAPERFrom(v *CellsToActivateListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellsToActivateListValueCodecFieldCapture(v *CellsToActivateListValueCodec) *func(CellsToActivateList, aper.DecodeState) (CellsToActivateList, aper.Snapshot) {
	return &v.capture
}
func BridgeCellsToActivateListValueCodecFieldCompare(v *CellsToActivateListValueCodec) *func(CellsToActivateList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellsToActivateListValueCodecFieldContext(v *CellsToActivateListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellsToActivateListValueCodecFieldDecode(v *CellsToActivateListValueCodec) *func([]byte, aper.DecodeState) (CellsToActivateList, error) {
	return &v.decode
}
func BridgeCellsToActivateListValueCodecFieldEncode(v *CellsToActivateListValueCodec) *func(CellsToActivateList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellsToActivateListValueCodecFieldPath(v *CellsToActivateListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCriticalityDiagnosticsIEItemMethodMarshalAPERTo(v *CriticalityDiagnosticsIEItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERFrom(v *CriticalityDiagnosticsIEItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.DecodeState) (CriticalityDiagnosticsIEList, aper.Snapshot) {
	return &v.capture
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(v *CriticalityDiagnosticsIEListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(v *CriticalityDiagnosticsIEListValueCodec) *func([]byte, aper.DecodeState) (CriticalityDiagnosticsIEList, error) {
	return &v.decode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(v *CriticalityDiagnosticsIEListValueCodec) *func(CriticalityDiagnosticsIEList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(v *CriticalityDiagnosticsIEListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSRequestInfoFieldPerPadding(v *DAPSRequestInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDAPSRequestInfoFieldReceived(v *DAPSRequestInfo) *bool { return &v.received }
func BridgeDAPSRequestInfoFieldReceivedBytes(v *DAPSRequestInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDAPSRequestInfoFieldReceivedLocation(v *DAPSRequestInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeDAPSRequestInfoMethodMarshalAPERBudget(v *DAPSRequestInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDAPSRequestInfoMethodUnmarshalAPERFrom(v *DAPSRequestInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSRequestInfoValueCodecFieldCapture(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, aper.DecodeState) (DAPSRequestInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSRequestInfoValueCodecFieldCompare(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSRequestInfoValueCodecFieldContext(v *DAPSRequestInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSRequestInfoValueCodecFieldDecode(v *DAPSRequestInfoValueCodec) *func([]byte, aper.DecodeState) (DAPSRequestInfo, error) {
	return &v.decode
}
func BridgeDAPSRequestInfoValueCodecFieldEncode(v *DAPSRequestInfoValueCodec) *func(DAPSRequestInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSRequestInfoValueCodecFieldPath(v *DAPSRequestInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldCapture(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, aper.DecodeState) (DAPSResponseInfoListIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldCompare(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldContext(v *DAPSResponseInfoListIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(v *DAPSResponseInfoListIEContainerValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEContainer, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(v *DAPSResponseInfoListIEContainerValueCodec) *func(DAPSResponseInfoListIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEContainerValueCodecFieldPath(v *DAPSResponseInfoListIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEFieldFieldReplay(v *DAPSResponseInfoListIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v *DAPSResponseInfoListIEField) *bool {
	return &v.withoutReplay
}
func BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(v *DAPSResponseInfoListIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(v *DAPSResponseInfoListIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldCapture(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, aper.DecodeState) (DAPSResponseInfoListIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldCompare(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldContext(v *DAPSResponseInfoListIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldDecode(v *DAPSResponseInfoListIEFieldValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEField, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldEncode(v *DAPSResponseInfoListIEFieldValueCodec) *func(DAPSResponseInfoListIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEFieldValueCodecFieldPath(v *DAPSResponseInfoListIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueFieldId(v *DAPSResponseInfoListIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDAPSResponseInfoListIEValueFieldIsOpaque(v *DAPSResponseInfoListIEValue) *bool {
	return &v.isOpaque
}
func BridgeDAPSResponseInfoListIEValueFieldOpaque(v *DAPSResponseInfoListIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDAPSResponseInfoListIEValueFieldRowDAPSResponseInfoItem(v *DAPSResponseInfoListIEValue) **DAPSResponseInfoItem {
	return &v.rowDAPSResponseInfoItem
}
func BridgeDAPSResponseInfoListIEValueMethodCaptureSemantics(v DAPSResponseInfoListIEValue, a0 aper.SemanticCapture) DAPSResponseInfoListIEValue {
	return v.captureSemantics(a0)
}
func BridgeDAPSResponseInfoListIEValueMethodCompareSemantics(v DAPSResponseInfoListIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDAPSResponseInfoListIEValueMethodMatchesID(v DAPSResponseInfoListIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDAPSResponseInfoListIEValueMethodRule(v DAPSResponseInfoListIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCapture(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCompare(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldContext(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldDecode(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoListIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldEncode(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *func(DAPSResponseInfoListIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldPath(v *DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDAPSResponseInfoListValueCodecFieldCapture(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, aper.DecodeState) (DAPSResponseInfoList, aper.Snapshot) {
	return &v.capture
}
func BridgeDAPSResponseInfoListValueCodecFieldCompare(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDAPSResponseInfoListValueCodecFieldContext(v *DAPSResponseInfoListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDAPSResponseInfoListValueCodecFieldDecode(v *DAPSResponseInfoListValueCodec) *func([]byte, aper.DecodeState) (DAPSResponseInfoList, error) {
	return &v.decode
}
func BridgeDAPSResponseInfoListValueCodecFieldEncode(v *DAPSResponseInfoListValueCodec) *func(DAPSResponseInfoList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDAPSResponseInfoListValueCodecFieldPath(v *DAPSResponseInfoListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget(v *DLCOUNTPDCPSNlength, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDLCPSecurityInformationFieldPerPadding(v *DLCPSecurityInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDLCPSecurityInformationFieldReceived(v *DLCPSecurityInformation) *bool { return &v.received }
func BridgeDLCPSecurityInformationFieldReceivedBytes(v *DLCPSecurityInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDLCPSecurityInformationFieldReceivedLocation(v *DLCPSecurityInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeDLCPSecurityInformationMethodMarshalAPERBudget(v *DLCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDLCPSecurityInformationMethodUnmarshalAPERFrom(v *DLCPSecurityInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDLCPSecurityInformationValueCodecFieldCapture(v *DLCPSecurityInformationValueCodec) *func(DLCPSecurityInformation, aper.DecodeState) (DLCPSecurityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeDLCPSecurityInformationValueCodecFieldCompare(v *DLCPSecurityInformationValueCodec) *func(DLCPSecurityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDLCPSecurityInformationValueCodecFieldContext(v *DLCPSecurityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCPSecurityInformationValueCodecFieldDecode(v *DLCPSecurityInformationValueCodec) *func([]byte, aper.DecodeState) (DLCPSecurityInformation, error) {
	return &v.decode
}
func BridgeDLCPSecurityInformationValueCodecFieldEncode(v *DLCPSecurityInformationValueCodec) *func(DLCPSecurityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLCPSecurityInformationValueCodecFieldPath(v *DLCPSecurityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeDLDiscardingMethodMarshalAPERBudget(v *DLDiscarding, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *BearersSubjectToDLDiscardingItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 351:
		if value, ok := v.AsBearersSubjectToDLDiscardingItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *BearersSubjectToEarlyStatusTransferItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 322:
		if value, ok := v.AsBearersSubjectToEarlyStatusTransferItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *DAPSResponseInfoListIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 319:
		if value, ok := v.AsDAPSResponseInfoItem(); ok {
			return value, true
		}
	}
	return nil, false
}
