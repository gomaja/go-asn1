// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s15 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s15

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} of TS 36.413: a single information element field.
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer = BearersSubjectToEarlyStatusTransferItemIEField

// BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{Bearers-SubjectToDLDiscarding-ItemIEs}} of TS 36.413: a single information element field.
type BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer = BearersSubjectToDLDiscardingItemIEField

// ERABDataForwardingItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABDataForwardingItemIEs}} of TS 36.413: a single information element field.
type ERABDataForwardingItemIEValueProtocolIESingleContainer = ERABDataForwardingItemIEField

// ERABAdmittedItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABAdmittedItemIEs}} of TS 36.413: a single information element field.
type ERABAdmittedItemIEValueProtocolIESingleContainer = ERABAdmittedItemIEField

// ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABFailedToResumeItemResumeReqIEs}} of TS 36.413: a single information element field.
type ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer = ERABFailedToResumeItemResumeReqIEField

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
	inject func(s14.BearersSubjectToEarlyStatusTransferItem,

	) BearersSubjectToEarlyStatusTransferItemIEValue

	get func(*BearersSubjectToEarlyStatusTransferItemIEValue,

	) (*s14.BearersSubjectToEarlyStatusTransferItem,

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
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) New(value s14.BearersSubjectToEarlyStatusTransferItem,

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
func (b BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) Get(field *BearersSubjectToEarlyStatusTransferItemIEField) (*s14.BearersSubjectToEarlyStatusTransferItem,

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
	decode  func([]byte, aper.DecodeState) (s14.BearersSubjectToEarlyStatusTransferItem,

		error)
	encode func(s14.BearersSubjectToEarlyStatusTransferItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s14.BearersSubjectToEarlyStatusTransferItem, aper.DecodeState,

	) (s14.BearersSubjectToEarlyStatusTransferItem, aper.Snapshot,

	)
	compare func(s14.BearersSubjectToEarlyStatusTransferItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) New(value s14.BearersSubjectToEarlyStatusTransferItem,

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
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) encodeBudgetValue(value s14.BearersSubjectToEarlyStatusTransferItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToEarlyStatusTransferItemValueCodec) encodeChanged(value s14.BearersSubjectToEarlyStatusTransferItem,

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

// ENBX2ExtTLAsValueCodec is the concrete ValueCodec[ENBX2ExtTLAs].
type ENBX2ExtTLAsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBX2ExtTLAs,

		error)
	encode func(ENBX2ExtTLAs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBX2ExtTLAs, aper.DecodeState,

	) (ENBX2ExtTLAs, aper.Snapshot,

	)
	compare func(ENBX2ExtTLAs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBX2ExtTLAsValueCodec) New(value ENBX2ExtTLAs,

) (ENBX2ExtTLAsAPERValue, error) {
	if c.encode == nil {
		return ENBX2ExtTLAsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBX2ExtTLAsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBX2ExtTLAsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBX2ExtTLAsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBX2ExtTLAsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBX2ExtTLAsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBX2ExtTLAsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBX2ExtTLAsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBX2ExtTLAsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBX2ExtTLAsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBX2ExtTLAsValueCodec) EncodeAPER(value ENBX2ExtTLAsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBX2ExtTLAsValueCodec) encodeBudgetValue(value ENBX2ExtTLAs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBX2ExtTLAsValueCodec) encodeChanged(value ENBX2ExtTLAs,

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

// ERABAdmittedItemERABAdmittedItemIEBinding binds ERABAdmittedItem to the E-RABAdmittedItemIEs object set of TS 36.413.
type ERABAdmittedItemERABAdmittedItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABAdmittedItemValueCodec
	inject func(ERABAdmittedItem,

	) ERABAdmittedItemIEValue

	get func(*ERABAdmittedItemIEValue,

	) (*ERABAdmittedItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABAdmittedItemERABAdmittedItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABAdmittedItemERABAdmittedItemIEBinding) Codec() ERABAdmittedItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABAdmittedItemERABAdmittedItemIEBinding) New(value ERABAdmittedItem,

) (ERABAdmittedItemIEField, error) {
	if b.inject == nil {
		return ERABAdmittedItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABAdmittedItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABAdmittedItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABAdmittedItemERABAdmittedItemIEBinding) Get(field *ERABAdmittedItemIEField) (*ERABAdmittedItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABAdmittedItemValueCodec is the concrete ValueCodec[ERABAdmittedItem].
type ERABAdmittedItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItem,

		error)
	encode func(ERABAdmittedItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItem, aper.DecodeState,

	) (ERABAdmittedItem, aper.Snapshot,

	)
	compare func(ERABAdmittedItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemValueCodec) New(value ERABAdmittedItem,

) (ERABAdmittedItemAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemValueCodec) EncodeAPER(value ERABAdmittedItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemValueCodec) encodeBudgetValue(value ERABAdmittedItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemValueCodec) encodeChanged(value ERABAdmittedItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemIEField is ProtocolIE-Field {{E-RABAdmittedItemIEs}} of TS 36.413: an information element field.
type ERABAdmittedItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABAdmittedItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEField) WithoutReplay() ERABAdmittedItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABAdmittedItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABAdmittedItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABAdmittedItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABAdmittedItemIEField{}
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
	var zero ERABAdmittedItemIEValue

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

// ERABDataForwardingItemERABDataForwardingItemIEBinding binds ERABDataForwardingItem to the E-RABDataForwardingItemIEs object set of TS 36.413.
type ERABDataForwardingItemERABDataForwardingItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABDataForwardingItemValueCodec
	inject func(ERABDataForwardingItem,

	) ERABDataForwardingItemIEValue

	get func(*ERABDataForwardingItemIEValue,

	) (*ERABDataForwardingItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABDataForwardingItemERABDataForwardingItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABDataForwardingItemERABDataForwardingItemIEBinding) Codec() ERABDataForwardingItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABDataForwardingItemERABDataForwardingItemIEBinding) New(value ERABDataForwardingItem,

) (ERABDataForwardingItemIEField, error) {
	if b.inject == nil {
		return ERABDataForwardingItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABDataForwardingItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABDataForwardingItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABDataForwardingItemERABDataForwardingItemIEBinding) Get(field *ERABDataForwardingItemIEField) (*ERABDataForwardingItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABDataForwardingItemValueCodec is the concrete ValueCodec[ERABDataForwardingItem].
type ERABDataForwardingItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItem,

		error)
	encode func(ERABDataForwardingItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItem, aper.DecodeState,

	) (ERABDataForwardingItem, aper.Snapshot,

	)
	compare func(ERABDataForwardingItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemValueCodec) New(value ERABDataForwardingItem,

) (ERABDataForwardingItemAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemValueCodec) EncodeAPER(value ERABDataForwardingItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemValueCodec) encodeBudgetValue(value ERABDataForwardingItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemValueCodec) encodeChanged(value ERABDataForwardingItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEField is ProtocolIE-Field {{E-RABDataForwardingItemIEs}} of TS 36.413: an information element field.
type ERABDataForwardingItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABDataForwardingItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEField) WithoutReplay() ERABDataForwardingItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABDataForwardingItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABDataForwardingItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABDataForwardingItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABDataForwardingItemIEField{}
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
	var zero ERABDataForwardingItemIEValue

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

// ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding binds ERABFailedToResumeItemResumeReq to the E-RABFailedToResumeItemResumeReqIEs object set of TS 36.413.
type ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding struct {
	info   s00.FieldInfo
	codec  ERABFailedToResumeItemResumeReqValueCodec
	inject func(ERABFailedToResumeItemResumeReq,

	) ERABFailedToResumeItemResumeReqIEValue

	get func(*ERABFailedToResumeItemResumeReqIEValue,

	) (*ERABFailedToResumeItemResumeReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) Codec() ERABFailedToResumeItemResumeReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) New(value ERABFailedToResumeItemResumeReq,

) (ERABFailedToResumeItemResumeReqIEField, error) {
	if b.inject == nil {
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) Get(field *ERABFailedToResumeItemResumeReqIEField) (*ERABFailedToResumeItemResumeReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABFailedToResumeItemResumeReqValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReq].
type ERABFailedToResumeItemResumeReqValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReq,

		error)
	encode func(ERABFailedToResumeItemResumeReq,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReq, aper.DecodeState,

	) (ERABFailedToResumeItemResumeReq, aper.Snapshot,

	)
	compare func(ERABFailedToResumeItemResumeReq, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqValueCodec) New(value ERABFailedToResumeItemResumeReq,

) (ERABFailedToResumeItemResumeReqAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReq,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReq,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEField is ProtocolIE-Field {{E-RABFailedToResumeItemResumeReqIEs}} of TS 36.413: an information element field.
type ERABFailedToResumeItemResumeReqIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABFailedToResumeItemResumeReqIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEField) WithoutReplay() ERABFailedToResumeItemResumeReqIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeReqIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeReqIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABFailedToResumeItemResumeReqIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeReqIEField{}
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
	var zero ERABFailedToResumeItemResumeReqIEValue

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

// ERABFailedToResumeItemResumeResIEField is ProtocolIE-Field {{E-RABFailedToResumeItemResumeResIEs}} of TS 36.413: an information element field.
type ERABFailedToResumeItemResumeResIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABFailedToResumeItemResumeResIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResIEField) WithoutReplay() ERABFailedToResumeItemResumeResIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedToResumeItemResumeResIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedToResumeItemResumeResIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABFailedToResumeItemResumeResIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeResIEField{}
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
	var zero ERABFailedToResumeItemResumeResIEValue

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

// ERABAdmittedListValueCodec is the concrete ValueCodec[ERABAdmittedList].
type ERABAdmittedListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedList,

		error)
	encode func(ERABAdmittedList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedList, aper.DecodeState,

	) (ERABAdmittedList, aper.Snapshot,

	)
	compare func(ERABAdmittedList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedListValueCodec) New(value ERABAdmittedList,

) (ERABAdmittedListAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedListValueCodec) EncodeAPER(value ERABAdmittedListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedListValueCodec) encodeBudgetValue(value ERABAdmittedList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedListValueCodec) encodeChanged(value ERABAdmittedList,

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

// DLCOUNTPDCPSNlengthValueCodec is the concrete ValueCodec[DLCOUNTPDCPSNlength].
type DLCOUNTPDCPSNlengthValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s14.DLCOUNTPDCPSNlength,

		error)
	encode func(s14.DLCOUNTPDCPSNlength,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s14.DLCOUNTPDCPSNlength, aper.DecodeState,

	) (s14.DLCOUNTPDCPSNlength, aper.Snapshot,

	)
	compare func(s14.DLCOUNTPDCPSNlength, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DLCOUNTPDCPSNlengthValueCodec) New(value s14.DLCOUNTPDCPSNlength,

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
func (c DLCOUNTPDCPSNlengthValueCodec) encodeBudgetValue(value s14.DLCOUNTPDCPSNlength,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DLCOUNTPDCPSNlengthValueCodec) encodeChanged(value s14.DLCOUNTPDCPSNlength,

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

// DeactivateTraceValueCodec is the concrete ValueCodec[DeactivateTrace].
type DeactivateTraceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DeactivateTrace,

		error)
	encode func(DeactivateTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DeactivateTrace, aper.DecodeState,

	) (DeactivateTrace, aper.Snapshot,

	)
	compare func(DeactivateTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DeactivateTraceValueCodec) New(value DeactivateTrace,

) (DeactivateTraceAPERValue, error) {
	if c.encode == nil {
		return DeactivateTraceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DeactivateTraceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DeactivateTraceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DeactivateTraceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DeactivateTraceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DeactivateTraceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DeactivateTraceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DeactivateTraceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DeactivateTraceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DeactivateTraceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DeactivateTraceValueCodec) EncodeAPER(value DeactivateTraceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DeactivateTraceValueCodec) encodeBudgetValue(value DeactivateTrace,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DeactivateTraceValueCodec) encodeChanged(value DeactivateTrace,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNonUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[DownlinkNonUEAssociatedLPPaTransport].
type DownlinkNonUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransport,

		error)
	encode func(DownlinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNonUEAssociatedLPPaTransportValueCodec) New(value DownlinkNonUEAssociatedLPPaTransport,

) (DownlinkNonUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNonUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNonUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNonUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNonUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNonUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNonUEAssociatedLPPaTransportValueCodec) EncodeAPER(value DownlinkNonUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNonUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value DownlinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNonUEAssociatedLPPaTransportValueCodec) encodeChanged(value DownlinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[DownlinkUEAssociatedLPPaTransport].
type DownlinkUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransport,

		error)
	encode func(DownlinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (DownlinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(DownlinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkUEAssociatedLPPaTransportValueCodec) New(value DownlinkUEAssociatedLPPaTransport,

) (DownlinkUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return DownlinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkUEAssociatedLPPaTransportValueCodec) EncodeAPER(value DownlinkUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value DownlinkUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkUEAssociatedLPPaTransportValueCodec) encodeChanged(value DownlinkUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EHRPDCompositeAvailableCapacityValueCodec is the concrete ValueCodec[EHRPDCompositeAvailableCapacity].
type EHRPDCompositeAvailableCapacityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EHRPDCompositeAvailableCapacity,

		error)
	encode func(EHRPDCompositeAvailableCapacity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EHRPDCompositeAvailableCapacity, aper.DecodeState,

	) (EHRPDCompositeAvailableCapacity, aper.Snapshot,

	)
	compare func(EHRPDCompositeAvailableCapacity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EHRPDCompositeAvailableCapacityValueCodec) New(value EHRPDCompositeAvailableCapacity,

) (EHRPDCompositeAvailableCapacityAPERValue, error) {
	if c.encode == nil {
		return EHRPDCompositeAvailableCapacityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EHRPDCompositeAvailableCapacityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EHRPDCompositeAvailableCapacityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EHRPDCompositeAvailableCapacityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EHRPDCompositeAvailableCapacityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EHRPDCompositeAvailableCapacityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EHRPDCompositeAvailableCapacityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EHRPDCompositeAvailableCapacityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EHRPDCompositeAvailableCapacityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EHRPDCompositeAvailableCapacityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EHRPDCompositeAvailableCapacityValueCodec) EncodeAPER(value EHRPDCompositeAvailableCapacityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EHRPDCompositeAvailableCapacityValueCodec) encodeBudgetValue(value EHRPDCompositeAvailableCapacity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EHRPDCompositeAvailableCapacityValueCodec) encodeChanged(value EHRPDCompositeAvailableCapacity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EHRPDMultiSectorLoadReportingResponseItemValueCodec is the concrete ValueCodec[EHRPDMultiSectorLoadReportingResponseItem].
type EHRPDMultiSectorLoadReportingResponseItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EHRPDMultiSectorLoadReportingResponseItem,

		error)
	encode func(EHRPDMultiSectorLoadReportingResponseItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EHRPDMultiSectorLoadReportingResponseItem, aper.DecodeState,

	) (EHRPDMultiSectorLoadReportingResponseItem, aper.Snapshot,

	)
	compare func(EHRPDMultiSectorLoadReportingResponseItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EHRPDMultiSectorLoadReportingResponseItemValueCodec) New(value EHRPDMultiSectorLoadReportingResponseItem,

) (EHRPDMultiSectorLoadReportingResponseItemAPERValue, error) {
	if c.encode == nil {
		return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EHRPDMultiSectorLoadReportingResponseItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EHRPDMultiSectorLoadReportingResponseItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EHRPDMultiSectorLoadReportingResponseItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EHRPDMultiSectorLoadReportingResponseItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EHRPDMultiSectorLoadReportingResponseItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EHRPDMultiSectorLoadReportingResponseItemValueCodec) EncodeAPER(value EHRPDMultiSectorLoadReportingResponseItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EHRPDMultiSectorLoadReportingResponseItemValueCodec) encodeBudgetValue(value EHRPDMultiSectorLoadReportingResponseItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EHRPDMultiSectorLoadReportingResponseItemValueCodec) encodeChanged(value EHRPDMultiSectorLoadReportingResponseItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EHRPDSectorLoadReportingResponseValueCodec is the concrete ValueCodec[EHRPDSectorLoadReportingResponse].
type EHRPDSectorLoadReportingResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EHRPDSectorLoadReportingResponse,

		error)
	encode func(EHRPDSectorLoadReportingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EHRPDSectorLoadReportingResponse, aper.DecodeState,

	) (EHRPDSectorLoadReportingResponse, aper.Snapshot,

	)
	compare func(EHRPDSectorLoadReportingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EHRPDSectorLoadReportingResponseValueCodec) New(value EHRPDSectorLoadReportingResponse,

) (EHRPDSectorLoadReportingResponseAPERValue, error) {
	if c.encode == nil {
		return EHRPDSectorLoadReportingResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EHRPDSectorLoadReportingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EHRPDSectorLoadReportingResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EHRPDSectorLoadReportingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EHRPDSectorLoadReportingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EHRPDSectorLoadReportingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EHRPDSectorLoadReportingResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EHRPDSectorLoadReportingResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EHRPDSectorLoadReportingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EHRPDSectorLoadReportingResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EHRPDSectorLoadReportingResponseValueCodec) EncodeAPER(value EHRPDSectorLoadReportingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EHRPDSectorLoadReportingResponseValueCodec) encodeBudgetValue(value EHRPDSectorLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EHRPDSectorLoadReportingResponseValueCodec) encodeChanged(value EHRPDSectorLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBIDValueCodec is the concrete ValueCodec[ENBID].
type ENBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBID,

		error)
	encode func(ENBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBID, aper.DecodeState,

	) (ENBID, aper.Snapshot,

	)
	compare func(ENBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBIDValueCodec) New(value ENBID,

) (ENBIDAPERValue, error) {
	if c.encode == nil {
		return ENBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBIDValueCodec) EncodeAPER(value ENBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBIDValueCodec) encodeBudgetValue(value ENBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBIDValueCodec) encodeChanged(value ENBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBX2ExtTLAValueCodec is the concrete ValueCodec[ENBX2ExtTLA].
type ENBX2ExtTLAValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBX2ExtTLA,

		error)
	encode func(ENBX2ExtTLA,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBX2ExtTLA, aper.DecodeState,

	) (ENBX2ExtTLA, aper.Snapshot,

	)
	compare func(ENBX2ExtTLA, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBX2ExtTLAValueCodec) New(value ENBX2ExtTLA,

) (ENBX2ExtTLAAPERValue, error) {
	if c.encode == nil {
		return ENBX2ExtTLAAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBX2ExtTLAAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBX2ExtTLAAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBX2ExtTLAAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBX2ExtTLAValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBX2ExtTLAAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBX2ExtTLAAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBX2ExtTLAAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBX2ExtTLAAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBX2ExtTLAAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBX2ExtTLAValueCodec) EncodeAPER(value ENBX2ExtTLAAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBX2ExtTLAValueCodec) encodeBudgetValue(value ENBX2ExtTLA,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBX2ExtTLAValueCodec) encodeChanged(value ENBX2ExtTLA,

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

// ERABAdmittedItemIEContainer is ProtocolIE-Container {{E-RABAdmittedItemIEs}} of TS 36.413: a list of ERABAdmittedItemIEField values.
type ERABAdmittedItemIEContainer []ERABAdmittedItemIEField

// ERABFailedToResumeItemResumeReqIEContainer is ProtocolIE-Container {{E-RABFailedToResumeItemResumeReqIEs}} of TS 36.413: a list of ERABFailedToResumeItemResumeReqIEField values.
type ERABFailedToResumeItemResumeReqIEContainer []ERABFailedToResumeItemResumeReqIEField

// ERABFailedToResumeItemResumeResIEContainer is ProtocolIE-Container {{E-RABFailedToResumeItemResumeResIEs}} of TS 36.413: a list of ERABFailedToResumeItemResumeResIEField values.
type ERABFailedToResumeItemResumeResIEContainer []ERABFailedToResumeItemResumeResIEField

// ERABDataForwardingItemIEContainer is ProtocolIE-Container {{E-RABDataForwardingItemIEs}} of TS 36.413: a list of ERABDataForwardingItemIEField values.
type ERABDataForwardingItemIEContainer []ERABDataForwardingItemIEField

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
	Value   s14.BearersSubjectToEarlyStatusTransferItem

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

// ENBX2ExtTLAsAPERValue is the concrete APERValue[ENBX2ExtTLAs].
type ENBX2ExtTLAsAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBX2ExtTLAs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBX2ExtTLAsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAsAPERValue) WithoutReplay() ENBX2ExtTLAsAPERValue {
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

// ERABAdmittedItemAPERValue is the concrete APERValue[ERABAdmittedItem].
type ERABAdmittedItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABAdmittedItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemAPERValue) WithoutReplay() ERABAdmittedItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemAPERValue is the concrete APERValue[ERABDataForwardingItem].
type ERABDataForwardingItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABDataForwardingItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemAPERValue) WithoutReplay() ERABDataForwardingItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReq].
type ERABFailedToResumeItemResumeReqAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABFailedToResumeItemResumeReq

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeResAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeRes].
type ERABFailedToResumeItemResumeResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABFailedToResumeItemResumeRes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResAPERValue) WithoutReplay() ERABFailedToResumeItemResumeResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABAdmittedListAPERValue is the concrete APERValue[ERABAdmittedList].
type ERABAdmittedListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABAdmittedList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedListAPERValue) WithoutReplay() ERABAdmittedListAPERValue {
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

// DLCOUNTPDCPSNlengthAPERValue is the concrete APERValue[DLCOUNTPDCPSNlength].
type DLCOUNTPDCPSNlengthAPERValue struct {
	context s00.BridgeCodecContext
	Value   s14.DLCOUNTPDCPSNlength

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

// DeactivateTraceAPERValue is the concrete APERValue[DeactivateTrace].
type DeactivateTraceAPERValue struct {
	context s00.BridgeCodecContext
	Value   DeactivateTrace

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DeactivateTraceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DeactivateTraceAPERValue) WithoutReplay() DeactivateTraceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNonUEAssociatedLPPaTransportAPERValue is the concrete APERValue[DownlinkNonUEAssociatedLPPaTransport].
type DownlinkNonUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   DownlinkNonUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNonUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNonUEAssociatedLPPaTransportAPERValue) WithoutReplay() DownlinkNonUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkUEAssociatedLPPaTransportAPERValue is the concrete APERValue[DownlinkUEAssociatedLPPaTransport].
type DownlinkUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   DownlinkUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkUEAssociatedLPPaTransportAPERValue) WithoutReplay() DownlinkUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EHRPDCompositeAvailableCapacityAPERValue is the concrete APERValue[EHRPDCompositeAvailableCapacity].
type EHRPDCompositeAvailableCapacityAPERValue struct {
	context s00.BridgeCodecContext
	Value   EHRPDCompositeAvailableCapacity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EHRPDCompositeAvailableCapacityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EHRPDCompositeAvailableCapacityAPERValue) WithoutReplay() EHRPDCompositeAvailableCapacityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EHRPDMultiSectorLoadReportingResponseItemAPERValue is the concrete APERValue[EHRPDMultiSectorLoadReportingResponseItem].
type EHRPDMultiSectorLoadReportingResponseItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   EHRPDMultiSectorLoadReportingResponseItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EHRPDMultiSectorLoadReportingResponseItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EHRPDMultiSectorLoadReportingResponseItemAPERValue) WithoutReplay() EHRPDMultiSectorLoadReportingResponseItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EHRPDSectorLoadReportingResponseAPERValue is the concrete APERValue[EHRPDSectorLoadReportingResponse].
type EHRPDSectorLoadReportingResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   EHRPDSectorLoadReportingResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EHRPDSectorLoadReportingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EHRPDSectorLoadReportingResponseAPERValue) WithoutReplay() EHRPDSectorLoadReportingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBIDAPERValue is the concrete APERValue[ENBID].
type ENBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBIDAPERValue) WithoutReplay() ENBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBX2ExtTLAAPERValue is the concrete APERValue[ENBX2ExtTLA].
type ENBX2ExtTLAAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBX2ExtTLA

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBX2ExtTLAAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBX2ExtTLAAPERValue) WithoutReplay() ENBX2ExtTLAAPERValue {
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

// ERABAdmittedItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABAdmittedItemIEValueERABIEContainerList].
type ERABAdmittedItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueERABIEContainerList, error)
	encode  func(ERABAdmittedItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemIEValueERABIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemIEValueERABIEContainerListValueCodec) New(value ERABAdmittedItemIEValueERABIEContainerList) (ERABAdmittedItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABAdmittedItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABAdmittedItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABAdmittedItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABAdmittedItemIEs}} of TS 36.413: a list of information element fields.
type ERABAdmittedItemIEValueERABIEContainerList []ERABAdmittedItemIEValueProtocolIESingleContainer

// ERABDataForwardingItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABDataForwardingItemIEValueERABIEContainerList].
type ERABDataForwardingItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueERABIEContainerList, error)
	encode  func(ERABDataForwardingItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemIEValueERABIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemIEValueERABIEContainerListValueCodec) New(value ERABDataForwardingItemIEValueERABIEContainerList) (ERABDataForwardingItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABDataForwardingItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABDataForwardingItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABDataForwardingItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABDataForwardingItemIEs}} of TS 36.413: a list of information element fields.
type ERABDataForwardingItemIEValueERABIEContainerList []ERABDataForwardingItemIEValueProtocolIESingleContainer

// ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqIEValueERABIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, error)
	encode  func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) New(value ERABFailedToResumeItemResumeReqIEValueERABIEContainerList) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABFailedToResumeItemResumeReqIEs}} of TS 36.413: a list of information element fields.
type ERABFailedToResumeItemResumeReqIEValueERABIEContainerList []ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer

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

// ERABAdmittedItemIEFieldValueCodec is the concrete ValueCodec[ERABAdmittedItemIEField].
type ERABAdmittedItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemIEField, error)
	encode  func(ERABAdmittedItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemIEField, aper.DecodeState) (ERABAdmittedItemIEField, aper.Snapshot)
	compare func(ERABAdmittedItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemIEFieldValueCodec) New(value ERABAdmittedItemIEField) (ERABAdmittedItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemIEFieldValueCodec) EncodeAPER(value ERABAdmittedItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemIEFieldValueCodec) encodeBudgetValue(value ERABAdmittedItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemIEFieldValueCodec) encodeChanged(value ERABAdmittedItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEFieldValueCodec is the concrete ValueCodec[ERABDataForwardingItemIEField].
type ERABDataForwardingItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemIEField, error)
	encode  func(ERABDataForwardingItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemIEField, aper.DecodeState) (ERABDataForwardingItemIEField, aper.Snapshot)
	compare func(ERABDataForwardingItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemIEFieldValueCodec) New(value ERABDataForwardingItemIEField) (ERABDataForwardingItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemIEFieldValueCodec) EncodeAPER(value ERABDataForwardingItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemIEFieldValueCodec) encodeBudgetValue(value ERABDataForwardingItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemIEFieldValueCodec) encodeChanged(value ERABDataForwardingItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEFieldValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqIEField].
type ERABFailedToResumeItemResumeReqIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEField, error)
	encode  func(ERABFailedToResumeItemResumeReqIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqIEField, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEField, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqIEFieldValueCodec) New(value ERABFailedToResumeItemResumeReqIEField) (ERABFailedToResumeItemResumeReqIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqIEFieldValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqIEFieldValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqIEFieldValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// ERABAdmittedItemIEContainerValueCodec is the concrete ValueCodec[ERABAdmittedItemIEContainer].
type ERABAdmittedItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemIEContainer, error)
	encode  func(ERABAdmittedItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemIEContainer, aper.DecodeState) (ERABAdmittedItemIEContainer, aper.Snapshot)
	compare func(ERABAdmittedItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemIEContainerValueCodec) New(value ERABAdmittedItemIEContainer) (ERABAdmittedItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemIEContainerValueCodec) EncodeAPER(value ERABAdmittedItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemIEContainerValueCodec) encodeBudgetValue(value ERABAdmittedItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemIEContainerValueCodec) encodeChanged(value ERABAdmittedItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEContainerValueCodec is the concrete ValueCodec[ERABDataForwardingItemIEContainer].
type ERABDataForwardingItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemIEContainer, error)
	encode  func(ERABDataForwardingItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemIEContainer, aper.DecodeState) (ERABDataForwardingItemIEContainer, aper.Snapshot)
	compare func(ERABDataForwardingItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemIEContainerValueCodec) New(value ERABDataForwardingItemIEContainer) (ERABDataForwardingItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemIEContainerValueCodec) EncodeAPER(value ERABDataForwardingItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemIEContainerValueCodec) encodeBudgetValue(value ERABDataForwardingItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemIEContainerValueCodec) encodeChanged(value ERABDataForwardingItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEContainerValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqIEContainer].
type ERABFailedToResumeItemResumeReqIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEContainer, error)
	encode  func(ERABFailedToResumeItemResumeReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqIEContainer, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqIEContainerValueCodec) New(value ERABFailedToResumeItemResumeReqIEContainer) (ERABFailedToResumeItemResumeReqIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqIEContainerValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqIEContainerValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqIEContainerValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABAdmittedItemIEValueProtocolErrorIEContainerList].
type ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABAdmittedItemIEValueProtocolErrorIEContainerList) (ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABAdmittedItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABAdmittedItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABAdmittedItemIEs}} of TS 36.413: a list of information element fields.
type ERABAdmittedItemIEValueProtocolErrorIEContainerList []ERABAdmittedItemIEValueProtocolIESingleContainer

// ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABDataForwardingItemIEValueProtocolErrorIEContainerList].
type ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABDataForwardingItemIEValueProtocolErrorIEContainerList) (ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABDataForwardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABDataForwardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABDataForwardingItemIEs}} of TS 36.413: a list of information element fields.
type ERABDataForwardingItemIEValueProtocolErrorIEContainerList []ERABDataForwardingItemIEValueProtocolIESingleContainer

// ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) New(value ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABFailedToResumeItemResumeReqIEs}} of TS 36.413: a list of information element fields.
type ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList []ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer

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

// ERABAdmittedItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABAdmittedItemIEValueProtocolIEContainerList].
type ERABAdmittedItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueProtocolIEContainerList, error)
	encode  func(ERABAdmittedItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABAdmittedItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) New(value ERABAdmittedItemIEValueProtocolIEContainerList) (ERABAdmittedItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABAdmittedItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABAdmittedItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABAdmittedItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABAdmittedItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABAdmittedItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABAdmittedItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABAdmittedItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABAdmittedItemIEValueProtocolIEContainerList []ERABAdmittedItemIEValueProtocolIESingleContainer

// ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABDataForwardingItemIEValueProtocolIEContainerList].
type ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolIEContainerList, error)
	encode  func(ERABDataForwardingItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABDataForwardingItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) New(value ERABDataForwardingItemIEValueProtocolIEContainerList) (ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABDataForwardingItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABDataForwardingItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABDataForwardingItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABDataForwardingItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABDataForwardingItemIEValueProtocolIEContainerList []ERABDataForwardingItemIEValueProtocolIESingleContainer

// ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, error)
	encode  func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) New(value ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABFailedToResumeItemResumeReqIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList []ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer

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

// ERABAdmittedItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABAdmittedItemIEValueERABIEContainerList].
type ERABAdmittedItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABAdmittedItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABDataForwardingItemIEValueERABIEContainerList].
type ERABDataForwardingItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABDataForwardingItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqIEValueERABIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue {
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

// ERABAdmittedItemIEFieldAPERValue is the concrete APERValue[ERABAdmittedItemIEField].
type ERABAdmittedItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEFieldAPERValue) WithoutReplay() ERABAdmittedItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemIEFieldAPERValue is the concrete APERValue[ERABDataForwardingItemIEField].
type ERABDataForwardingItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEFieldAPERValue) WithoutReplay() ERABDataForwardingItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqIEFieldAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqIEField].
type ERABFailedToResumeItemResumeReqIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEFieldAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqIEFieldAPERValue {
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

// ERABAdmittedItemIEContainerAPERValue is the concrete APERValue[ERABAdmittedItemIEContainer].
type ERABAdmittedItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEContainerAPERValue) WithoutReplay() ERABAdmittedItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemIEContainerAPERValue is the concrete APERValue[ERABDataForwardingItemIEContainer].
type ERABDataForwardingItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEContainerAPERValue) WithoutReplay() ERABDataForwardingItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqIEContainerAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqIEContainer].
type ERABFailedToResumeItemResumeReqIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEContainerAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeResIEContainerAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeResIEContainer].
type ERABFailedToResumeItemResumeResIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeResIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeResIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeResIEContainerAPERValue) WithoutReplay() ERABFailedToResumeItemResumeResIEContainerAPERValue {
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

// ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABAdmittedItemIEValueProtocolErrorIEContainerList].
type ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABDataForwardingItemIEValueProtocolErrorIEContainerList].
type ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue {
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

// ERABAdmittedItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABAdmittedItemIEValueProtocolIEContainerList].
type ERABAdmittedItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABAdmittedItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABAdmittedItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABDataForwardingItemIEValueProtocolIEContainerList].
type ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABDataForwardingItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList].
type ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue {
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
	s12.BridgeBearersSubjectToDLDiscardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s12.BridgeBearersSubjectToDLDiscardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s14.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(v.rowBearersSubjectToEarlyStatusTransferItem, s)
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
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s14.BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(v.rowBearersSubjectToEarlyStatusTransferItem, s)
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
func BridgeCaptureS1APDLCPSecurityInformation(v *DLCPSecurityInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APDLNASMAC(&v.DlNASMAC, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeDLCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s13.BridgeDLCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
				s14.BridgeCaptureS1APCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength15 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
				s14.BridgeCaptureS1APCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, nil, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength18 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
				s14.BridgeCaptureS1APCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, s)
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
				s14.BridgeCompareS1APCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength15 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
				s14.BridgeCompareS1APCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		{
			f := s.Begin()
			s.Bool(v.DiscardDLCOUNTValuePDCPSNlength18 == nil)
			if v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
				s14.BridgeCompareS1APCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDeactivateTrace(v *DeactivateTrace, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDeactivateTraceIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDeactivateTrace(v *DeactivateTrace, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDeactivateTraceIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransport(v *DownlinkNonUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransport(v *DownlinkNonUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDownlinkUEAssociatedLPPaTransport(v *DownlinkUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDownlinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDownlinkUEAssociatedLPPaTransport(v *DownlinkUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeDownlinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEHRPDCompositeAvailableCapacity(v *EHRPDCompositeAvailableCapacity, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEHRPDSectorCapacityClassValue(&v.EHRPDSectorCapacityClassValue, s)
	s00.BridgeCaptureS1APEHRPDCapacityValue(&v.EHRPDCapacityValue, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEHRPDCompositeAvailableCapacity(v *EHRPDCompositeAvailableCapacity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEHRPDSectorCapacityClassValue(&v.EHRPDSectorCapacityClassValue, s)
	s02.BridgeCompareS1APEHRPDCapacityValue(&v.EHRPDCapacityValue, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEHRPDMultiSectorLoadReportingResponseItem(v *EHRPDMultiSectorLoadReportingResponseItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEHRPDSectorID(&v.EHRPDSectorID, s)
	BridgeCaptureS1APEHRPDSectorLoadReportingResponse(&v.EHRPDSectorLoadReportingResponse, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(v *EHRPDMultiSectorLoadReportingResponseItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEHRPDSectorID(&v.EHRPDSectorID, s)
	BridgeCompareS1APEHRPDSectorLoadReportingResponse(&v.EHRPDSectorLoadReportingResponse, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEHRPDSectorLoadReportingResponse(v *EHRPDSectorLoadReportingResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APEHRPDCompositeAvailableCapacity(&v.DLEHRPDCompositeAvailableCapacity, s)
	BridgeCaptureS1APEHRPDCompositeAvailableCapacity(&v.ULEHRPDCompositeAvailableCapacity, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEHRPDSectorLoadReportingResponse(v *EHRPDSectorLoadReportingResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APEHRPDCompositeAvailableCapacity(&v.DLEHRPDCompositeAvailableCapacity, s)
	BridgeCompareS1APEHRPDCompositeAvailableCapacity(&v.ULEHRPDCompositeAvailableCapacity, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBID(v *ENBID, s *aper.SemanticCapture) {
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
	case s00.ENBIDChoiceMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.MacroENBID == nil)
			if v.MacroENBID != nil {
				s.BitString((*v.MacroENBID).Bytes, (*v.MacroENBID).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.ENBIDChoiceHomeENBID:
		{
			f := s.Begin()
			s.Bool(v.HomeENBID == nil)
			if v.HomeENBID != nil {
				s.BitString((*v.HomeENBID).Bytes, (*v.HomeENBID).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.ENBIDChoiceShortMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.ShortMacroENBID == nil)
			if v.ShortMacroENBID != nil {
				s.BitString((*v.ShortMacroENBID).Bytes, (*v.ShortMacroENBID).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.ENBIDChoiceLongMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.LongMacroENBID == nil)
			if v.LongMacroENBID != nil {
				s.BitString((*v.LongMacroENBID).Bytes, (*v.LongMacroENBID).BitLength)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APENBID(v *ENBID, s *aper.SemanticComparison) {
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
	case s00.ENBIDChoiceMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.MacroENBID == nil)
			if v.MacroENBID != nil {
				s.BitString((*v.MacroENBID).Bytes, (*v.MacroENBID).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.ENBIDChoiceHomeENBID:
		{
			f := s.Begin()
			s.Bool(v.HomeENBID == nil)
			if v.HomeENBID != nil {
				s.BitString((*v.HomeENBID).Bytes, (*v.HomeENBID).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.ENBIDChoiceShortMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.ShortMacroENBID == nil)
			if v.ShortMacroENBID != nil {
				s.BitString((*v.ShortMacroENBID).Bytes, (*v.ShortMacroENBID).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.ENBIDChoiceLongMacroENBID:
		{
			f := s.Begin()
			s.Bool(v.LongMacroENBID == nil)
			if v.LongMacroENBID != nil {
				s.BitString((*v.LongMacroENBID).Bytes, (*v.LongMacroENBID).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APENBX2ExtTLA(v *ENBX2ExtTLA, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.IPsecTLA == nil)
		if v.IPsecTLA != nil {
			s00.BridgeCaptureS1APTransportLayerAddress(v.IPsecTLA, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.GTPTLAa == nil)
	s00.BridgeCaptureS1APENBX2GTPTLAs(&v.GTPTLAa, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENBX2ExtTLAExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2ExtTLA(v *ENBX2ExtTLA, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.IPsecTLA == nil)
		if v.IPsecTLA != nil {
			s07.BridgeCompareS1APTransportLayerAddress(v.IPsecTLA, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.GTPTLAa == nil)
	s07.BridgeCompareS1APENBX2GTPTLAs(&v.GTPTLAa, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENBX2ExtTLAExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABAdmittedItem(v *ERABAdmittedItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	{
		f := s.Begin()
		s.Bool(v.DLTransportLayerAddress == nil)
		if v.DLTransportLayerAddress != nil {
			s00.BridgeCaptureS1APTransportLayerAddress(v.DLTransportLayerAddress, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.DLGTPTEID == nil)
		if v.DLGTPTEID != nil {
			s00.BridgeCaptureS1APGTPTEID(v.DLGTPTEID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULTransportLayerAddress == nil)
		if v.ULTransportLayerAddress != nil {
			s00.BridgeCaptureS1APTransportLayerAddress(v.ULTransportLayerAddress, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULGTPTEID == nil)
		if v.ULGTPTEID != nil {
			s00.BridgeCaptureS1APGTPTEID(v.ULGTPTEID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABAdmittedItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABAdmittedItem(v *ERABAdmittedItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	{
		f := s.Begin()
		s.Bool(v.DLTransportLayerAddress == nil)
		if v.DLTransportLayerAddress != nil {
			s07.BridgeCompareS1APTransportLayerAddress(v.DLTransportLayerAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.DLGTPTEID == nil)
		if v.DLGTPTEID != nil {
			s02.BridgeCompareS1APGTPTEID(v.DLGTPTEID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULTransportLayerAddress == nil)
		if v.ULTransportLayerAddress != nil {
			s07.BridgeCompareS1APTransportLayerAddress(v.ULTransportLayerAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULGTPTEID == nil)
		if v.ULGTPTEID != nil {
			s02.BridgeCompareS1APGTPTEID(v.ULGTPTEID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABAdmittedItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABAdmittedItemIEValue(v *ERABAdmittedItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowERABAdmittedItem == nil)
				if v.rowERABAdmittedItem != nil {
					BridgeCaptureS1APERABAdmittedItem(v.rowERABAdmittedItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABAdmittedItemIEValue) captureSemantics(s aper.SemanticCapture) ERABAdmittedItemIEValue {
	BridgeCaptureS1APERABAdmittedItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABAdmittedItemIEValue(v *ERABAdmittedItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowERABAdmittedItem == nil)
				if v.rowERABAdmittedItem != nil {
					BridgeCompareS1APERABAdmittedItem(v.rowERABAdmittedItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABAdmittedItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABAdmittedItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABDataForwardingItem(v *ERABDataForwardingItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.DLTransportLayerAddress == nil)
		if v.DLTransportLayerAddress != nil {
			s00.BridgeCaptureS1APTransportLayerAddress(v.DLTransportLayerAddress, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.DLGTPTEID == nil)
		if v.DLGTPTEID != nil {
			s00.BridgeCaptureS1APGTPTEID(v.DLGTPTEID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULTransportLayerAddress == nil)
		if v.ULTransportLayerAddress != nil {
			s00.BridgeCaptureS1APTransportLayerAddress(v.ULTransportLayerAddress, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULGTPTEID == nil)
		if v.ULGTPTEID != nil {
			s00.BridgeCaptureS1APGTPTEID(v.ULGTPTEID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABDataForwardingItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABDataForwardingItem(v *ERABDataForwardingItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	{
		f := s.Begin()
		s.Bool(v.DLTransportLayerAddress == nil)
		if v.DLTransportLayerAddress != nil {
			s07.BridgeCompareS1APTransportLayerAddress(v.DLTransportLayerAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.DLGTPTEID == nil)
		if v.DLGTPTEID != nil {
			s02.BridgeCompareS1APGTPTEID(v.DLGTPTEID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULTransportLayerAddress == nil)
		if v.ULTransportLayerAddress != nil {
			s07.BridgeCompareS1APTransportLayerAddress(v.ULTransportLayerAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ULGTPTEID == nil)
		if v.ULGTPTEID != nil {
			s02.BridgeCompareS1APGTPTEID(v.ULGTPTEID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABDataForwardingItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABDataForwardingItemIEValue(v *ERABDataForwardingItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowERABDataForwardingItem == nil)
				if v.rowERABDataForwardingItem != nil {
					BridgeCaptureS1APERABDataForwardingItem(v.rowERABDataForwardingItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABDataForwardingItemIEValue) captureSemantics(s aper.SemanticCapture) ERABDataForwardingItemIEValue {
	BridgeCaptureS1APERABDataForwardingItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABDataForwardingItemIEValue(v *ERABDataForwardingItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowERABDataForwardingItem == nil)
				if v.rowERABDataForwardingItem != nil {
					BridgeCompareS1APERABDataForwardingItem(v.rowERABDataForwardingItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABDataForwardingItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABDataForwardingItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABFailedToResumeItemResumeReq(v *ERABFailedToResumeItemResumeReq, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s14.BridgeCaptureS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToResumeItemResumeReqExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedToResumeItemResumeReq(v *ERABFailedToResumeItemResumeReq, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s14.BridgeCompareS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToResumeItemResumeReqExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABFailedToResumeItemResumeReqIEValue(v *ERABFailedToResumeItemResumeReqIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(236):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeItemResumeReq == nil)
				if v.rowERABFailedToResumeItemResumeReq != nil {
					BridgeCaptureS1APERABFailedToResumeItemResumeReq(v.rowERABFailedToResumeItemResumeReq, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedToResumeItemResumeReqIEValue) captureSemantics(s aper.SemanticCapture) ERABFailedToResumeItemResumeReqIEValue {
	BridgeCaptureS1APERABFailedToResumeItemResumeReqIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABFailedToResumeItemResumeReqIEValue(v *ERABFailedToResumeItemResumeReqIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(236):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeItemResumeReq == nil)
				if v.rowERABFailedToResumeItemResumeReq != nil {
					BridgeCompareS1APERABFailedToResumeItemResumeReq(v.rowERABFailedToResumeItemResumeReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedToResumeItemResumeReqIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABFailedToResumeItemResumeReqIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABFailedToResumeItemResumeRes(v *ERABFailedToResumeItemResumeRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s14.BridgeCaptureS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToResumeItemResumeResExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedToResumeItemResumeRes(v *ERABFailedToResumeItemResumeRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s14.BridgeCompareS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToResumeItemResumeResExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABFailedToResumeItemResumeResIEValue(v *ERABFailedToResumeItemResumeResIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(238):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeItemResumeRes == nil)
				if v.rowERABFailedToResumeItemResumeRes != nil {
					BridgeCaptureS1APERABFailedToResumeItemResumeRes(v.rowERABFailedToResumeItemResumeRes, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedToResumeItemResumeResIEValue) captureSemantics(s aper.SemanticCapture) ERABFailedToResumeItemResumeResIEValue {
	BridgeCaptureS1APERABFailedToResumeItemResumeResIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABFailedToResumeItemResumeResIEValue(v *ERABFailedToResumeItemResumeResIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(238):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeItemResumeRes == nil)
				if v.rowERABFailedToResumeItemResumeRes != nil {
					BridgeCompareS1APERABFailedToResumeItemResumeRes(v.rowERABFailedToResumeItemResumeRes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedToResumeItemResumeResIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABFailedToResumeItemResumeResIEValue(&v, &s)
	return s
}

type BearersSubjectToEarlyStatusTransferList = []BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
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
	IEExtensions      s07.BearersSubjectToDLDiscardingItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                   `asn1:"-" json:"-"`
	extCount          int64                                                  `asn1:"-" json:"-"`
	extPresent        []bool                                                 `asn1:"-" json:"-"`
	extData           [][]byte                                               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
	IEExtensions      s08.DLCPSecurityInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
	DiscardDLCOUNTValuePDCPSNlength12 *s14.COUNTvalue               `json:"DiscardDLCOUNTValuePDCPSNlength12,omitempty"`
	DiscardDLCOUNTValuePDCPSNlength15 *s14.COUNTValueExtended       `json:"DiscardDLCOUNTValuePDCPSNlength15,omitempty"`
	DiscardDLCOUNTValuePDCPSNlength18 *s14.COUNTvaluePDCPSNlength18 `json:"DiscardDLCOUNTValuePDCPSNlength18,omitempty"`
}

// ENBID represents the ASN.1 CHOICE type ENB-ID.
type ENBID struct {
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
	MacroENBID         *runtime.BitString    `json:"MacroENBID,omitempty"`
	HomeENBID          *runtime.BitString    `json:"HomeENBID,omitempty"`
	ShortMacroENBID    *runtime.BitString    `json:"ShortMacroENBID,omitempty"`
	LongMacroENBID     *runtime.BitString    `json:"LongMacroENBID,omitempty"`
}
type ENBX2ExtTLAs = []ENBX2ExtTLA

// ENBX2ExtTLA represents the ASN.1 type ENBX2ExtTLA (SEQUENCE).
type ENBX2ExtTLA struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	IPsecTLA          *s00.TransportLayerAddress        `asn1:"tag:0,context,implicit,optional" json:"IPsecTLA,omitempty"`
	GTPTLAa           s00.ENBX2GTPTLAs                  `asn1:"tag:1,context,implicit,optional" json:"GTPTLAa,omitzero"`
	gTPTLAaIndef      bool                              `asn1:"-" json:"-"`
	IEExtensions      s08.ENBX2ExtTLAExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
				if err := s07.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToDLDiscardingItem from APER format.
func (v *BearersSubjectToDLDiscardingItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToDLDiscardingItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
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
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *BearersSubjectToDLDiscardingItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToDLDiscardingItem{}
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
		tmp_ieextensions := make(s07.BearersSubjectToDLDiscardingItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.BearersSubjectToDLDiscardingItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s07.BridgeBearersSubjectToDLDiscardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DLCPSecurityInformation from APER format.
func (v *DLCPSecurityInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DLCPSecurityInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
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
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DLCPSecurityInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DLCPSecurityInformation{}
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
	bsBytes_dlnasmac, bsBitLen_dlnasmac, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "DlNASMAC")
	}
	v.DlNASMAC = runtime.BitString{Bytes: bsBytes_dlnasmac, BitLength: bsBitLen_dlnasmac}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.DLCPSecurityInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.DLCPSecurityInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeDLCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		if err := s14.BridgeCOUNTvalueMethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength12, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding discardDLCOUNTValuePDCP-SNlength12: %w", err)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		if v.DiscardDLCOUNTValuePDCPSNlength15 == nil {
			return fmt.Errorf("choice alternative discardDLCOUNTValuePDCP-SNlength15 is nil")
		}
		if err := s14.BridgeCOUNTValueExtendedMethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength15, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding discardDLCOUNTValuePDCP-SNlength15: %w", err)
		}
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		if v.DiscardDLCOUNTValuePDCPSNlength18 == nil {
			return fmt.Errorf("choice alternative discardDLCOUNTValuePDCP-SNlength18 is nil")
		}
		if err := s14.BridgeCOUNTvaluePDCPSNlength18MethodMarshalAPERTo(v.DiscardDLCOUNTValuePDCPSNlength18, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPERWithOptions decodes DLDiscarding with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
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
		var dec_discarddlcountvaluepdcpsnlength12 s14.COUNTvalue
		if err := s14.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength12, bb); err != nil {
			return runtime.WrapDecodePath(err, "DiscardDLCOUNTValuePDCPSNlength12")
		}
		if err := aper.ChargeValue(bb, dec_discarddlcountvaluepdcpsnlength12); err != nil {
			return err
		}
		v.DiscardDLCOUNTValuePDCPSNlength12 = &dec_discarddlcountvaluepdcpsnlength12
		bb.LeaveComponent(toleranceMark_discarddlcountvaluepdcpsnlength12)
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15:
		toleranceMark_discarddlcountvaluepdcpsnlength15 := bb.EnterComponent("DiscardDLCOUNTValuePDCPSNlength15")
		var dec_discarddlcountvaluepdcpsnlength15 s14.COUNTValueExtended
		if err := s14.BridgeCOUNTValueExtendedMethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength15, bb); err != nil {
			return runtime.WrapDecodePath(err, "DiscardDLCOUNTValuePDCPSNlength15")
		}
		if err := aper.ChargeValue(bb, dec_discarddlcountvaluepdcpsnlength15); err != nil {
			return err
		}
		v.DiscardDLCOUNTValuePDCPSNlength15 = &dec_discarddlcountvaluepdcpsnlength15
		bb.LeaveComponent(toleranceMark_discarddlcountvaluepdcpsnlength15)
	case s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18:
		toleranceMark_discarddlcountvaluepdcpsnlength18 := bb.EnterComponent("DiscardDLCOUNTValuePDCPSNlength18")
		var dec_discarddlcountvaluepdcpsnlength18 s14.COUNTvaluePDCPSNlength18
		if err := s14.BridgeCOUNTvaluePDCPSNlength18MethodUnmarshalAPERFrom(&dec_discarddlcountvaluepdcpsnlength18, bb); err != nil {
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

// MarshalAPER encodes ENBID to APER format.
func (v *ENBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *ENBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "ENBID:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "ENBID:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 2 {
			return fmt.Errorf("%s extension index %d is known to this schema", "ENBID:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "ENBID:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.ENBIDChoiceShortMacroENBID:
			if v.ShortMacroENBID == nil {
				return fmt.Errorf("choice alternative short-macroENB-ID is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.ShortMacroENBID.Bytes, v.ShortMacroENBID.BitLength, 18, 18, true); err != nil {
				return fmt.Errorf("encoding short-macroENB-ID: %w", err)
			}
		case s00.ENBIDChoiceLongMacroENBID:
			if v.LongMacroENBID == nil {
				return fmt.Errorf("choice alternative long-macroENB-ID is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.LongMacroENBID.Bytes, v.LongMacroENBID.BitLength, 21, 21, true); err != nil {
				return fmt.Errorf("encoding long-macroENB-ID: %w", err)
			}
		default:
			return fmt.Errorf("unknown ENBID extension choice %d", v.Choice)
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
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.ENBIDChoiceMacroENBID:
		if v.MacroENBID == nil {
			return fmt.Errorf("choice alternative macroENB-ID is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.MacroENBID.Bytes, v.MacroENBID.BitLength, 20, 20, true); err != nil {
			return fmt.Errorf("encoding macroENB-ID: %w", err)
		}
	case s00.ENBIDChoiceHomeENBID:
		if v.HomeENBID == nil {
			return fmt.Errorf("choice alternative homeENB-ID is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.HomeENBID.Bytes, v.HomeENBID.BitLength, 28, 28, true); err != nil {
			return fmt.Errorf("encoding homeENB-ID: %w", err)
		}
	default:
		return fmt.Errorf("unknown ENBID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ENBID from APER format.
func (v *ENBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBID")
	}
	bb.EnterComponent("ENBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *ENBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBID{}
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
		if extIdx >= 2 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(2) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.ENBIDChoiceShortMacroENBID:
			extensionPath = "ShortMacroENBID"
			bsBytes_shortmacroenbid, bsBitLen_shortmacroenbid, err := aper.DecodeBitStringAligned(inner, 18, 18, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "ShortMacroENBID")
			}
			tmp_shortmacroenbid := runtime.BitString{Bytes: bsBytes_shortmacroenbid, BitLength: bsBitLen_shortmacroenbid}
			if err := aper.ChargeValue(inner, tmp_shortmacroenbid); err != nil {
				return err
			}
			v.ShortMacroENBID = &tmp_shortmacroenbid
		case s00.ENBIDChoiceLongMacroENBID:
			extensionPath = "LongMacroENBID"
			bsBytes_longmacroenbid, bsBitLen_longmacroenbid, err := aper.DecodeBitStringAligned(inner, 21, 21, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "LongMacroENBID")
			}
			tmp_longmacroenbid := runtime.BitString{Bytes: bsBytes_longmacroenbid, BitLength: bsBitLen_longmacroenbid}
			if err := aper.ChargeValue(inner, tmp_longmacroenbid); err != nil {
				return err
			}
			v.LongMacroENBID = &tmp_longmacroenbid
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
	case s00.ENBIDChoiceMacroENBID:
		bsBytes_macroenbid, bsBitLen_macroenbid, err := aper.DecodeBitStringAligned(bb, 20, 20, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "MacroENBID")
		}
		tmp_macroenbid := runtime.BitString{Bytes: bsBytes_macroenbid, BitLength: bsBitLen_macroenbid}
		if err := aper.ChargeValue(bb, tmp_macroenbid); err != nil {
			return err
		}
		v.MacroENBID = &tmp_macroenbid
	case s00.ENBIDChoiceHomeENBID:
		bsBytes_homeenbid, bsBitLen_homeenbid, err := aper.DecodeBitStringAligned(bb, 28, 28, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "HomeENBID")
		}
		tmp_homeenbid := runtime.BitString{Bytes: bsBytes_homeenbid, BitLength: bsBitLen_homeenbid}
		if err := aper.ChargeValue(bb, tmp_homeenbid); err != nil {
			return err
		}
		v.HomeENBID = &tmp_homeenbid
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ENBX2ExtTLA to APER format.
func (v *ENBX2ExtTLA) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBX2ExtTLA) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.IPsecTLA != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.GTPTLAa != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.IPsecTLA != nil {
		if err := aper.EncodeBitStringAlignedExt(bb, v.IPsecTLA.Bytes, v.IPsecTLA.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding iPsecTLA: %w", err)
		}
	}
	if v.GTPTLAa != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.GTPTLAa)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_gtptlaa, fragmentLength_gtptlaa int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_gtptlaa < 0 || fragmentOffset_gtptlaa > int64(len(v.GTPTLAa)) || fragmentLength_gtptlaa < 0 || fragmentLength_gtptlaa > int64(len(v.GTPTLAa[fragmentOffset_gtptlaa:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.GTPTLAa[fragmentOffset_gtptlaa : fragmentOffset_gtptlaa+fragmentLength_gtptlaa] {
				if err := aper.EncodeBitStringAlignedExt(bb, elem.Bytes, elem.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding gTPTLAa element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding gTPTLAa: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBX2ExtTLA from APER format.
func (v *ENBX2ExtTLA) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBX2ExtTLA with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBX2ExtTLA) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLA")
	}
	bb.EnterComponent("ENBX2ExtTLA")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLA")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBX2ExtTLA")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLA")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBX2ExtTLA) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBX2ExtTLA{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ipsectla, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_gtptlaa, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_ipsectla {
		bsBytes_ipsectla, bsBitLen_ipsectla, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "IPsecTLA")
		}
		tmp_ipsectla := runtime.BitString{Bytes: bsBytes_ipsectla, BitLength: bsBitLen_ipsectla}
		if err := aper.ChargeValue(bb, tmp_ipsectla); err != nil {
			return err
		}
		v.IPsecTLA = &tmp_ipsectla
	}
	if opt_gtptlaa {
		toleranceMark_gtptlaa := bb.EnterComponent("GTPTLAa")
		tmp_gtptlaa := make(s00.ENBX2GTPTLAs, 0)
		_, errCollection_gtptlaa := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_gtptlaa, fragmentLength_gtptlaa int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1202
			if fragmentOffset_gtptlaa < 0 || fragmentLength_gtptlaa < 0 || fragmentLength_gtptlaa > int64(^uint(0)>>1) || fragmentOffset_gtptlaa > int64(^uint(0)>>1)-fragmentLength_gtptlaa {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_gtptlaa; i++ {
				elemBytes, elemBitLength, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("GTPTLAa[%d]", fragmentOffset_gtptlaa+i))
				}
				if next, err := aper.AppendValues(bb, tmp_gtptlaa, runtime.BitString{Bytes: elemBytes, BitLength: elemBitLength}); err != nil {
					return err
				} else {
					tmp_gtptlaa = next
				}
			}
			return nil
		})
		if errCollection_gtptlaa != nil {
			return runtime.WrapDecodePath(errCollection_gtptlaa, "GTPTLAa")
		}
		v.GTPTLAa = tmp_gtptlaa
		bb.LeaveComponent(toleranceMark_gtptlaa)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ENBX2ExtTLAExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENBX2ExtTLAExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeENBX2ExtTLAExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToDLDiscardingItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingItem", v.receivedLocation, v.perPadding)
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
func (v *DLCPSecurityInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DLCPSecurityInformation", v.receivedLocation, v.perPadding)
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
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DLDiscarding", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBID) WithoutReplay() ENBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBID
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBX2ExtTLA) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBX2ExtTLA", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBX2ExtTLA", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBX2ExtTLA) WithoutReplay() ENBX2ExtTLA {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBX2ExtTLA
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
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

// Extensions returns owned unknown sequence additions.
func (v *ENBX2ExtTLA) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBX2ExtTLA) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBX2ExtTLA.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBX2ExtTLA.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBX2ExtTLA) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBX2ExtTLA.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBX2ExtTLA.Extensions[%d]", index))
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBID")
}
func (v *ENBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBID")
}
func (v *ENBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBID(v, &s)
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
func (v *ENBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBX2ExtTLA) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBX2ExtTLA")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBX2ExtTLA) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBX2ExtTLA")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBX2ExtTLA(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBX2ExtTLA")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBX2ExtTLA")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBX2ExtTLA) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBX2ExtTLA")
}
func (v *ENBX2ExtTLA) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBX2ExtTLA")
}
func (v *ENBX2ExtTLA) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBX2ExtTLA(v, &s)
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
func (v *ENBX2ExtTLA) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBX2ExtTLA) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBID{}
		return report, aper.OperationError(err, "ENBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBX2ExtTLA) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBX2ExtTLA")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBX2ExtTLA
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBX2ExtTLA(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBX2ExtTLA{}
		return report, aper.OperationError(err, "ENBX2ExtTLA")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBX2ExtTLA")
}

// ERABDataForwardingItem represents the ASN.1 type E-RABDataForwardingItem (SEQUENCE).
type ERABDataForwardingItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	ERABID                  s00.ERABID                                   `asn1:"tag:0,context,implicit"`
	DLTransportLayerAddress *s00.TransportLayerAddress                   `asn1:"tag:1,context,implicit,optional" json:"DLTransportLayerAddress,omitempty"`
	DLGTPTEID               *s00.GTPTEID                                 `asn1:"tag:2,context,implicit,optional" json:"DLGTPTEID,omitempty"`
	ULTransportLayerAddress *s00.TransportLayerAddress                   `asn1:"tag:3,context,implicit,optional" json:"ULTransportLayerAddress,omitempty"`
	ULGTPTEID               *s00.GTPTEID                                 `asn1:"tag:4,context,implicit,optional" json:"ULGTPTEID,omitempty"`
	IEExtensions            s08.ERABDataForwardingItemExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                         `asn1:"-" json:"-"`
	extCount                int64                                        `asn1:"-" json:"-"`
	extPresent              []bool                                       `asn1:"-" json:"-"`
	extData                 [][]byte                                     `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}
type ERABAdmittedList = []ERABAdmittedItemIEValueProtocolIESingleContainer

// ERABAdmittedItem represents the ASN.1 type E-RABAdmittedItem (SEQUENCE).
type ERABAdmittedItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	ERABID                  s00.ERABID                             `asn1:"tag:0,context,implicit"`
	TransportLayerAddress   s00.TransportLayerAddress              `asn1:"tag:1,context,implicit"`
	GTPTEID                 s00.GTPTEID                            `asn1:"tag:2,context,implicit"`
	DLTransportLayerAddress *s00.TransportLayerAddress             `asn1:"tag:3,context,implicit,optional" json:"DLTransportLayerAddress,omitempty"`
	DLGTPTEID               *s00.GTPTEID                           `asn1:"tag:4,context,implicit,optional" json:"DLGTPTEID,omitempty"`
	ULTransportLayerAddress *s00.TransportLayerAddress             `asn1:"tag:5,context,implicit,optional" json:"ULTransportLayerAddress,omitempty"`
	ULGTPTEID               *s00.GTPTEID                           `asn1:"tag:6,context,implicit,optional" json:"ULGTPTEID,omitempty"`
	IEExtensions            s08.ERABAdmittedItemExtIEsExtContainer `asn1:"tag:7,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                   `asn1:"-" json:"-"`
	extCount                int64                                  `asn1:"-" json:"-"`
	extPresent              []bool                                 `asn1:"-" json:"-"`
	extData                 [][]byte                               `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// DeactivateTrace represents the ASN.1 type DeactivateTrace (SEQUENCE).
type DeactivateTrace struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s08.DeactivateTraceIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// DownlinkUEAssociatedLPPaTransport represents the ASN.1 type DownlinkUEAssociatedLPPaTransport (SEQUENCE).
type DownlinkUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s08.DownlinkUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// DownlinkNonUEAssociatedLPPaTransport represents the ASN.1 type DownlinkNonUEAssociatedLPPaTransport (SEQUENCE).
type DownlinkNonUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s08.DownlinkNonUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                                `asn1:"-" json:"-"`
	extCount         int64                                               `asn1:"-" json:"-"`
	extPresent       []bool                                              `asn1:"-" json:"-"`
	extData          [][]byte                                            `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABFailedToResumeItemResumeReq represents the ASN.1 type E-RABFailedToResumeItemResumeReq (SEQUENCE).
type ERABFailedToResumeItemResumeReq struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                            `asn1:"tag:0,context,implicit"`
	Cause             s14.Cause                                             `asn1:"tag:1,context,explicit"`
	IEExtensions      s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                  `asn1:"-" json:"-"`
	extCount          int64                                                 `asn1:"-" json:"-"`
	extPresent        []bool                                                `asn1:"-" json:"-"`
	extData           [][]byte                                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ERABFailedToResumeItemResumeRes represents the ASN.1 type E-RABFailedToResumeItemResumeRes (SEQUENCE).
type ERABFailedToResumeItemResumeRes struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                            `asn1:"tag:0,context,implicit"`
	Cause             s14.Cause                                             `asn1:"tag:1,context,explicit"`
	IEExtensions      s08.ERABFailedToResumeItemResumeResExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                  `asn1:"-" json:"-"`
	extCount          int64                                                 `asn1:"-" json:"-"`
	extPresent        []bool                                                `asn1:"-" json:"-"`
	extData           [][]byte                                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes ERABDataForwardingItem to APER format.
func (v *ERABDataForwardingItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABDataForwardingItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.DLTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.DLGTPTEID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ULTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ULGTPTEID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if v.DLTransportLayerAddress != nil {
		if err := aper.EncodeBitStringAlignedExt(bb, v.DLTransportLayerAddress.Bytes, v.DLTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding dL-transportLayerAddress: %w", err)
		}
	}
	if v.DLGTPTEID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.DLGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding dL-gTP-TEID: %w", err)
		}
	}
	if v.ULTransportLayerAddress != nil {
		if err := aper.EncodeBitStringAlignedExt(bb, v.ULTransportLayerAddress.Bytes, v.ULTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding uL-TransportLayerAddress: %w", err)
		}
	}
	if v.ULGTPTEID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.ULGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABDataForwardingItem from APER format.
func (v *ERABDataForwardingItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABDataForwardingItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABDataForwardingItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABDataForwardingItem")
	}
	bb.EnterComponent("ERABDataForwardingItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABDataForwardingItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABDataForwardingItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABDataForwardingItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABDataForwardingItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABDataForwardingItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dltransportlayeraddress, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_dlgtpteid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ultransportlayeraddress, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ulgtpteid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	if opt_dltransportlayeraddress {
		bsBytes_dltransportlayeraddress, bsBitLen_dltransportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLTransportLayerAddress")
		}
		tmp_dltransportlayeraddress := runtime.BitString{Bytes: bsBytes_dltransportlayeraddress, BitLength: bsBitLen_dltransportlayeraddress}
		if err := aper.ChargeValue(bb, tmp_dltransportlayeraddress); err != nil {
			return err
		}
		v.DLTransportLayerAddress = &tmp_dltransportlayeraddress
	}
	if opt_dlgtpteid {
		val_dlgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLGTPTEID")
		}
		tmp_dlgtpteid := s00.GTPTEID(val_dlgtpteid)
		if err := aper.ChargeValue(bb, tmp_dlgtpteid); err != nil {
			return err
		}
		v.DLGTPTEID = &tmp_dlgtpteid
	}
	if opt_ultransportlayeraddress {
		bsBytes_ultransportlayeraddress, bsBitLen_ultransportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULTransportLayerAddress")
		}
		tmp_ultransportlayeraddress := runtime.BitString{Bytes: bsBytes_ultransportlayeraddress, BitLength: bsBitLen_ultransportlayeraddress}
		if err := aper.ChargeValue(bb, tmp_ultransportlayeraddress); err != nil {
			return err
		}
		v.ULTransportLayerAddress = &tmp_ultransportlayeraddress
	}
	if opt_ulgtpteid {
		val_ulgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULGTPTEID")
		}
		tmp_ulgtpteid := s00.GTPTEID(val_ulgtpteid)
		if err := aper.ChargeValue(bb, tmp_ulgtpteid); err != nil {
			return err
		}
		v.ULGTPTEID = &tmp_ulgtpteid
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ERABDataForwardingItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABDataForwardingItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeERABDataForwardingItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABAdmittedItem to APER format.
func (v *ERABAdmittedItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABAdmittedItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.DLTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.DLGTPTEID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ULTransportLayerAddress != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ULGTPTEID != nil); err != nil {
		return err
	}
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
	if v.DLTransportLayerAddress != nil {
		if err := aper.EncodeBitStringAlignedExt(bb, v.DLTransportLayerAddress.Bytes, v.DLTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding dL-transportLayerAddress: %w", err)
		}
	}
	if v.DLGTPTEID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.DLGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding dL-gTP-TEID: %w", err)
		}
	}
	if v.ULTransportLayerAddress != nil {
		if err := aper.EncodeBitStringAlignedExt(bb, v.ULTransportLayerAddress.Bytes, v.ULTransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
			return fmt.Errorf("encoding uL-TransportLayerAddress: %w", err)
		}
	}
	if v.ULGTPTEID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.ULGTPTEID), 4, 4, true); err != nil {
			return fmt.Errorf("encoding uL-GTP-TEID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABAdmittedItem from APER format.
func (v *ERABAdmittedItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABAdmittedItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABAdmittedItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedItem")
	}
	bb.EnterComponent("ERABAdmittedItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABAdmittedItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABAdmittedItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABAdmittedItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_dltransportlayeraddress, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_dlgtpteid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ultransportlayeraddress, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ulgtpteid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
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
	if opt_dltransportlayeraddress {
		bsBytes_dltransportlayeraddress, bsBitLen_dltransportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLTransportLayerAddress")
		}
		tmp_dltransportlayeraddress := runtime.BitString{Bytes: bsBytes_dltransportlayeraddress, BitLength: bsBitLen_dltransportlayeraddress}
		if err := aper.ChargeValue(bb, tmp_dltransportlayeraddress); err != nil {
			return err
		}
		v.DLTransportLayerAddress = &tmp_dltransportlayeraddress
	}
	if opt_dlgtpteid {
		val_dlgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "DLGTPTEID")
		}
		tmp_dlgtpteid := s00.GTPTEID(val_dlgtpteid)
		if err := aper.ChargeValue(bb, tmp_dlgtpteid); err != nil {
			return err
		}
		v.DLGTPTEID = &tmp_dlgtpteid
	}
	if opt_ultransportlayeraddress {
		bsBytes_ultransportlayeraddress, bsBitLen_ultransportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULTransportLayerAddress")
		}
		tmp_ultransportlayeraddress := runtime.BitString{Bytes: bsBytes_ultransportlayeraddress, BitLength: bsBitLen_ultransportlayeraddress}
		if err := aper.ChargeValue(bb, tmp_ultransportlayeraddress); err != nil {
			return err
		}
		v.ULTransportLayerAddress = &tmp_ultransportlayeraddress
	}
	if opt_ulgtpteid {
		val_ulgtpteid, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ULGTPTEID")
		}
		tmp_ulgtpteid := s00.GTPTEID(val_ulgtpteid)
		if err := aper.ChargeValue(bb, tmp_ulgtpteid); err != nil {
			return err
		}
		v.ULGTPTEID = &tmp_ulgtpteid
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ERABAdmittedItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABAdmittedItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeERABAdmittedItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DeactivateTrace to APER format.
func (v *DeactivateTrace) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DeactivateTrace) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s08.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DeactivateTrace from APER format.
func (v *DeactivateTrace) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DeactivateTrace with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DeactivateTrace) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DeactivateTrace")
	}
	bb.EnterComponent("DeactivateTrace")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DeactivateTrace")
	}
	padding, err := aper.CaptureFinalBits(bb, "DeactivateTrace")
	if err != nil {
		return runtime.WrapDecodePath(err, "DeactivateTrace")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DeactivateTrace) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DeactivateTrace{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s08.DeactivateTraceIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s08.DeactivateTraceIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s08.BridgeDeactivateTraceIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DownlinkUEAssociatedLPPaTransport to APER format.
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DownlinkUEAssociatedLPPaTransport from APER format.
func (v *DownlinkUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DownlinkUEAssociatedLPPaTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DownlinkUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("DownlinkUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "DownlinkUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "DownlinkUEAssociatedLPPaTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DownlinkUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkUEAssociatedLPPaTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s08.DownlinkUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s08.DownlinkUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes DownlinkNonUEAssociatedLPPaTransport to APER format.
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes DownlinkNonUEAssociatedLPPaTransport from APER format.
func (v *DownlinkNonUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DownlinkNonUEAssociatedLPPaTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DownlinkNonUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("DownlinkNonUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "DownlinkNonUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DownlinkNonUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkNonUEAssociatedLPPaTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s08.DownlinkNonUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s08.DownlinkNonUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s08.BridgeDownlinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABFailedToResumeItemResumeReq to APER format.
func (v *ERABFailedToResumeItemResumeReq) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s14.BridgeCauseMethodMarshalAPERTo(&v.Cause, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cause: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABFailedToResumeItemResumeReq from APER format.
func (v *ERABFailedToResumeItemResumeReq) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABFailedToResumeItemResumeReq with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABFailedToResumeItemResumeReq) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
	}
	bb.EnterComponent("ERABFailedToResumeItemResumeReq")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABFailedToResumeItemResumeReq) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeReq{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_cause := bb.EnterComponent("Cause")
	if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&v.Cause, bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	bb.LeaveComponent(toleranceMark_cause)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ERABFailedToResumeItemResumeReqExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABFailedToResumeItemResumeReqExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeERABFailedToResumeItemResumeReqExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABFailedToResumeItemResumeRes to APER format.
func (v *ERABFailedToResumeItemResumeRes) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s14.BridgeCauseMethodMarshalAPERTo(&v.Cause, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cause: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABFailedToResumeItemResumeRes from APER format.
func (v *ERABFailedToResumeItemResumeRes) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABFailedToResumeItemResumeRes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABFailedToResumeItemResumeRes) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeRes")
	}
	bb.EnterComponent("ERABFailedToResumeItemResumeRes")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeItemResumeRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeRes")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABFailedToResumeItemResumeRes) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToResumeItemResumeRes{}
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
	val_erabid, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABID")
	}
	v.ERABID = val_erabid
	toleranceMark_cause := bb.EnterComponent("Cause")
	if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&v.Cause, bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	bb.LeaveComponent(toleranceMark_cause)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ERABFailedToResumeItemResumeResExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABFailedToResumeItemResumeResExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeERABFailedToResumeItemResumeResExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *DeactivateTrace) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DeactivateTrace", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DeactivateTrace", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DeactivateTrace) WithoutReplay() DeactivateTrace {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DeactivateTrace
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DownlinkNonUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DownlinkNonUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DownlinkNonUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DownlinkNonUEAssociatedLPPaTransport) WithoutReplay() DownlinkNonUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DownlinkNonUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DownlinkUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DownlinkUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DownlinkUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DownlinkUEAssociatedLPPaTransport) WithoutReplay() DownlinkUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DownlinkUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABAdmittedItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABAdmittedItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABAdmittedItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABAdmittedItem) WithoutReplay() ERABAdmittedItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABAdmittedItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABDataForwardingItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABDataForwardingItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABDataForwardingItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABDataForwardingItem) WithoutReplay() ERABDataForwardingItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABDataForwardingItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABFailedToResumeItemResumeReq) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedToResumeItemResumeReq", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedToResumeItemResumeReq", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedToResumeItemResumeReq) WithoutReplay() ERABFailedToResumeItemResumeReq {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedToResumeItemResumeReq
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABFailedToResumeItemResumeRes) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedToResumeItemResumeRes", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedToResumeItemResumeRes", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedToResumeItemResumeRes) WithoutReplay() ERABFailedToResumeItemResumeRes {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedToResumeItemResumeRes
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *DeactivateTrace) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DeactivateTrace) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DeactivateTrace.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DeactivateTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DeactivateTrace) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DeactivateTrace.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DeactivateTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DownlinkNonUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DownlinkNonUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DownlinkNonUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *DownlinkUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DownlinkUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DownlinkUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABAdmittedItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABAdmittedItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABAdmittedItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABAdmittedItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABAdmittedItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABAdmittedItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABAdmittedItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABDataForwardingItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABDataForwardingItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABDataForwardingItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABDataForwardingItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABDataForwardingItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABDataForwardingItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABDataForwardingItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABFailedToResumeItemResumeReq) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABFailedToResumeItemResumeReq) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToResumeItemResumeReq.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToResumeItemResumeReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABFailedToResumeItemResumeReq) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToResumeItemResumeReq.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToResumeItemResumeReq.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABFailedToResumeItemResumeRes) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABFailedToResumeItemResumeRes) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToResumeItemResumeRes.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToResumeItemResumeRes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABFailedToResumeItemResumeRes) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToResumeItemResumeRes.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToResumeItemResumeRes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *DeactivateTrace) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DeactivateTrace")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DeactivateTrace) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DeactivateTrace")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDeactivateTrace(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DeactivateTrace")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DeactivateTrace")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DeactivateTrace) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DeactivateTrace")
}
func (v *DeactivateTrace) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DeactivateTrace")
}
func (v *DeactivateTrace) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDeactivateTrace(v, &s)
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
func (v *DeactivateTrace) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DeactivateTrace) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DownlinkNonUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DownlinkNonUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DownlinkNonUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDownlinkNonUEAssociatedLPPaTransport(v, &s)
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
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DownlinkNonUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DownlinkUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DownlinkUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDownlinkUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DownlinkUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDownlinkUEAssociatedLPPaTransport(v, &s)
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
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DownlinkUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABAdmittedItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABAdmittedItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABAdmittedItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABAdmittedItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABAdmittedItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABAdmittedItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABAdmittedItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABAdmittedItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABAdmittedItem")
}
func (v *ERABAdmittedItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABAdmittedItem")
}
func (v *ERABAdmittedItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABAdmittedItem(v, &s)
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
func (v *ERABAdmittedItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABAdmittedItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABDataForwardingItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABDataForwardingItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABDataForwardingItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABDataForwardingItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABDataForwardingItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABDataForwardingItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABDataForwardingItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABDataForwardingItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABDataForwardingItem")
}
func (v *ERABDataForwardingItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABDataForwardingItem")
}
func (v *ERABDataForwardingItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABDataForwardingItem(v, &s)
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
func (v *ERABDataForwardingItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABDataForwardingItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABFailedToResumeItemResumeReq) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedToResumeItemResumeReq")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeItemResumeReq")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedToResumeItemResumeReq(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedToResumeItemResumeReq")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedToResumeItemResumeReq")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedToResumeItemResumeReq")
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedToResumeItemResumeReq")
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedToResumeItemResumeReq(v, &s)
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
func (v *ERABFailedToResumeItemResumeReq) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedToResumeItemResumeReq) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABFailedToResumeItemResumeRes) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedToResumeItemResumeRes")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeItemResumeRes")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedToResumeItemResumeRes(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedToResumeItemResumeRes")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedToResumeItemResumeRes")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedToResumeItemResumeRes")
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedToResumeItemResumeRes")
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedToResumeItemResumeRes(v, &s)
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
func (v *ERABFailedToResumeItemResumeRes) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedToResumeItemResumeRes) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DeactivateTrace) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DeactivateTrace")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DeactivateTrace
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDeactivateTrace(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DeactivateTrace{}
		return report, aper.OperationError(err, "DeactivateTrace")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DeactivateTrace")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DownlinkNonUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DownlinkNonUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DownlinkNonUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDownlinkNonUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DownlinkNonUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DownlinkNonUEAssociatedLPPaTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DownlinkUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DownlinkUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DownlinkUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDownlinkUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DownlinkUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DownlinkUEAssociatedLPPaTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABAdmittedItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABAdmittedItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABAdmittedItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABAdmittedItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABAdmittedItem{}
		return report, aper.OperationError(err, "ERABAdmittedItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABAdmittedItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABDataForwardingItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABDataForwardingItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABDataForwardingItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABDataForwardingItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABDataForwardingItem{}
		return report, aper.OperationError(err, "ERABDataForwardingItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABDataForwardingItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABFailedToResumeItemResumeReq) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeItemResumeReq")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedToResumeItemResumeReq
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedToResumeItemResumeReq(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedToResumeItemResumeReq{}
		return report, aper.OperationError(err, "ERABFailedToResumeItemResumeReq")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedToResumeItemResumeReq")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABFailedToResumeItemResumeRes) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeItemResumeRes")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedToResumeItemResumeRes
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedToResumeItemResumeRes(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedToResumeItemResumeRes{}
		return report, aper.OperationError(err, "ERABFailedToResumeItemResumeRes")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedToResumeItemResumeRes")
}

// EHRPDSectorLoadReportingResponse represents the ASN.1 type EHRPDSectorLoadReportingResponse (SEQUENCE).
type EHRPDSectorLoadReportingResponse struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	DLEHRPDCompositeAvailableCapacity EHRPDCompositeAvailableCapacity `asn1:"tag:0,context,implicit"`
	ULEHRPDCompositeAvailableCapacity EHRPDCompositeAvailableCapacity `asn1:"tag:1,context,implicit"`
	extCount                          int64                           `asn1:"-" json:"-"`
	extPresent                        []bool                          `asn1:"-" json:"-"`
	extData                           [][]byte                        `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// EHRPDCompositeAvailableCapacity represents the ASN.1 type EHRPDCompositeAvailableCapacity (SEQUENCE).
type EHRPDCompositeAvailableCapacity struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	EHRPDSectorCapacityClassValue s00.EHRPDSectorCapacityClassValue `asn1:"tag:0,context,implicit"`
	EHRPDCapacityValue            s00.EHRPDCapacityValue            `asn1:"tag:1,context,implicit"`
	extCount                      int64                             `asn1:"-" json:"-"`
	extPresent                    []bool                            `asn1:"-" json:"-"`
	extData                       [][]byte                          `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// EHRPDMultiSectorLoadReportingResponseItem represents the ASN.1 type EHRPDMultiSectorLoadReportingResponseItem (SEQUENCE).
type EHRPDMultiSectorLoadReportingResponseItem struct {
	replay                           aper.Snapshot
	stream                           aper.WireSpan
	received                         bool
	withoutReplay                    bool
	receivedAbsolute                 bool
	receivedBytes                    aper.WireSpan
	receivedLocation                 aper.Location
	EHRPDSectorID                    s00.EHRPDSectorID                `asn1:"tag:0,context,implicit"`
	EHRPDSectorLoadReportingResponse EHRPDSectorLoadReportingResponse `asn1:"tag:1,context,implicit"`
	extCount                         int64                            `asn1:"-" json:"-"`
	extPresent                       []bool                           `asn1:"-" json:"-"`
	extData                          [][]byte                         `asn1:"-" json:"-"`
	perPadding                       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding                    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin                        []aper.OpaqueOrigin
	extWire                          []aper.WireSpan
}

// MarshalAPER encodes EHRPDSectorLoadReportingResponse to APER format.
func (v *EHRPDSectorLoadReportingResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.DLEHRPDCompositeAvailableCapacity.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dL-EHRPD-CompositeAvailableCapacity: %w", err)
	}
	if err := v.ULEHRPDCompositeAvailableCapacity.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding uL-EHRPD-CompositeAvailableCapacity: %w", err)
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

// UnmarshalAPER decodes EHRPDSectorLoadReportingResponse from APER format.
func (v *EHRPDSectorLoadReportingResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EHRPDSectorLoadReportingResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDSectorLoadReportingResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	bb.EnterComponent("EHRPDSectorLoadReportingResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "EHRPDSectorLoadReportingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EHRPDSectorLoadReportingResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EHRPDSectorLoadReportingResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_dlehrpdcompositeavailablecapacity := bb.EnterComponent("DLEHRPDCompositeAvailableCapacity")
	if err := v.DLEHRPDCompositeAvailableCapacity.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DLEHRPDCompositeAvailableCapacity")
	}
	bb.LeaveComponent(toleranceMark_dlehrpdcompositeavailablecapacity)
	toleranceMark_ulehrpdcompositeavailablecapacity := bb.EnterComponent("ULEHRPDCompositeAvailableCapacity")
	if err := v.ULEHRPDCompositeAvailableCapacity.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULEHRPDCompositeAvailableCapacity")
	}
	bb.LeaveComponent(toleranceMark_ulehrpdcompositeavailablecapacity)
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

// MarshalAPER encodes EHRPDCompositeAvailableCapacity to APER format.
func (v *EHRPDCompositeAvailableCapacity) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.EHRPDSectorCapacityClassValue, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound2, true); err != nil {
		return fmt.Errorf("encoding eHRPDSectorCapacityClassValue: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.EHRPDCapacityValue), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding eHRPDCapacityValue: %w", err)
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

// UnmarshalAPER decodes EHRPDCompositeAvailableCapacity from APER format.
func (v *EHRPDCompositeAvailableCapacity) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EHRPDCompositeAvailableCapacity with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDCompositeAvailableCapacity) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	bb.EnterComponent("EHRPDCompositeAvailableCapacity")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	padding, err := aper.CaptureFinalBits(bb, "EHRPDCompositeAvailableCapacity")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCompositeAvailableCapacity")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EHRPDCompositeAvailableCapacity) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EHRPDCompositeAvailableCapacity{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorcapacityclassvalue, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorCapacityClassValue")
	}
	v.EHRPDSectorCapacityClassValue = val_ehrpdsectorcapacityclassvalue
	val_ehrpdcapacityvalue, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDCapacityValue")
	}
	v.EHRPDCapacityValue = s00.EHRPDCapacityValue(val_ehrpdcapacityvalue)
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

// MarshalAPER encodes EHRPDMultiSectorLoadReportingResponseItem to APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.EHRPDSectorID), 16, 16, true); err != nil {
		return fmt.Errorf("encoding eHRPD-Sector-ID: %w", err)
	}
	if err := v.EHRPDSectorLoadReportingResponse.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eHRPDSectorLoadReportingResponse: %w", err)
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

// UnmarshalAPER decodes EHRPDMultiSectorLoadReportingResponseItem from APER format.
func (v *EHRPDMultiSectorLoadReportingResponseItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EHRPDMultiSectorLoadReportingResponseItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EHRPDMultiSectorLoadReportingResponseItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	bb.EnterComponent("EHRPDMultiSectorLoadReportingResponseItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "EHRPDMultiSectorLoadReportingResponseItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EHRPDMultiSectorLoadReportingResponseItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ehrpdsectorid, err := aper.DecodeOctetStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorID")
	}
	v.EHRPDSectorID = s00.EHRPDSectorID(val_ehrpdsectorid)
	toleranceMark_ehrpdsectorloadreportingresponse := bb.EnterComponent("EHRPDSectorLoadReportingResponse")
	if err := v.EHRPDSectorLoadReportingResponse.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EHRPDSectorLoadReportingResponse")
	}
	bb.LeaveComponent(toleranceMark_ehrpdsectorloadreportingresponse)
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
func (v *EHRPDCompositeAvailableCapacity) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EHRPDCompositeAvailableCapacity", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EHRPDCompositeAvailableCapacity", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EHRPDCompositeAvailableCapacity) WithoutReplay() EHRPDCompositeAvailableCapacity {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EHRPDCompositeAvailableCapacity
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EHRPDMultiSectorLoadReportingResponseItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EHRPDMultiSectorLoadReportingResponseItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EHRPDMultiSectorLoadReportingResponseItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EHRPDMultiSectorLoadReportingResponseItem) WithoutReplay() EHRPDMultiSectorLoadReportingResponseItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EHRPDMultiSectorLoadReportingResponseItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EHRPDSectorLoadReportingResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EHRPDSectorLoadReportingResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EHRPDSectorLoadReportingResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EHRPDSectorLoadReportingResponse) WithoutReplay() EHRPDSectorLoadReportingResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EHRPDSectorLoadReportingResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *EHRPDCompositeAvailableCapacity) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EHRPDCompositeAvailableCapacity) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDCompositeAvailableCapacity.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDCompositeAvailableCapacity.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EHRPDCompositeAvailableCapacity) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDCompositeAvailableCapacity.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDCompositeAvailableCapacity.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EHRPDMultiSectorLoadReportingResponseItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EHRPDMultiSectorLoadReportingResponseItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDMultiSectorLoadReportingResponseItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDMultiSectorLoadReportingResponseItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EHRPDMultiSectorLoadReportingResponseItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDMultiSectorLoadReportingResponseItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDMultiSectorLoadReportingResponseItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EHRPDSectorLoadReportingResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EHRPDSectorLoadReportingResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDSectorLoadReportingResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDSectorLoadReportingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EHRPDSectorLoadReportingResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EHRPDSectorLoadReportingResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EHRPDSectorLoadReportingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EHRPDCompositeAvailableCapacity) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EHRPDCompositeAvailableCapacity")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EHRPDCompositeAvailableCapacity")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEHRPDCompositeAvailableCapacity(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EHRPDCompositeAvailableCapacity")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EHRPDCompositeAvailableCapacity")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EHRPDCompositeAvailableCapacity")
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EHRPDCompositeAvailableCapacity")
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEHRPDCompositeAvailableCapacity(v, &s)
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
func (v *EHRPDCompositeAvailableCapacity) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EHRPDCompositeAvailableCapacity) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EHRPDMultiSectorLoadReportingResponseItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EHRPDMultiSectorLoadReportingResponseItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EHRPDMultiSectorLoadReportingResponseItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EHRPDMultiSectorLoadReportingResponseItem")
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EHRPDMultiSectorLoadReportingResponseItem")
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(v, &s)
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
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EHRPDMultiSectorLoadReportingResponseItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EHRPDSectorLoadReportingResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EHRPDSectorLoadReportingResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EHRPDSectorLoadReportingResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEHRPDSectorLoadReportingResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EHRPDSectorLoadReportingResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EHRPDSectorLoadReportingResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EHRPDSectorLoadReportingResponse")
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EHRPDSectorLoadReportingResponse")
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEHRPDSectorLoadReportingResponse(v, &s)
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
func (v *EHRPDSectorLoadReportingResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EHRPDSectorLoadReportingResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EHRPDCompositeAvailableCapacity) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EHRPDCompositeAvailableCapacity")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EHRPDCompositeAvailableCapacity
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEHRPDCompositeAvailableCapacity(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EHRPDCompositeAvailableCapacity{}
		return report, aper.OperationError(err, "EHRPDCompositeAvailableCapacity")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EHRPDCompositeAvailableCapacity")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EHRPDMultiSectorLoadReportingResponseItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EHRPDMultiSectorLoadReportingResponseItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEHRPDMultiSectorLoadReportingResponseItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EHRPDMultiSectorLoadReportingResponseItem{}
		return report, aper.OperationError(err, "EHRPDMultiSectorLoadReportingResponseItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EHRPDMultiSectorLoadReportingResponseItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EHRPDSectorLoadReportingResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EHRPDSectorLoadReportingResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EHRPDSectorLoadReportingResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEHRPDSectorLoadReportingResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EHRPDSectorLoadReportingResponse{}
		return report, aper.OperationError(err, "EHRPDSectorLoadReportingResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EHRPDSectorLoadReportingResponse")
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
	rowBearersSubjectToEarlyStatusTransferItem *s14.BearersSubjectToEarlyStatusTransferItem
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
func (v *BearersSubjectToEarlyStatusTransferItemIEValue) AsBearersSubjectToEarlyStatusTransferItem() (*s14.BearersSubjectToEarlyStatusTransferItem, bool) {
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
		var value s14.BearersSubjectToEarlyStatusTransferItem
		child := scope
		if err := s14.BridgeBearersSubjectToEarlyStatusTransferItemMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToEarlyStatusTransferItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BearersSubjectToEarlyStatusTransferItem")
		if err != nil {
			return out, err
		}
		*s14.BridgeBearersSubjectToEarlyStatusTransferItemFieldPerPadding(&value) = padding
		*s14.BridgeBearersSubjectToEarlyStatusTransferItemFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeBearersSubjectToEarlyStatusTransferItemFieldReceivedBytes(&value))
		*s14.BridgeBearersSubjectToEarlyStatusTransferItemFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s14.BridgeBearersSubjectToEarlyStatusTransferItemMethodMarshalAPERBudget(v.rowBearersSubjectToEarlyStatusTransferItem, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToEarlyStatusTransferItemIEValue:", v.id)
	}
}

type ERABAdmittedItemIEValue struct {
	id                  s00.ProtocolIEID
	received            aper.WireSpan
	replay              aper.Snapshot
	opaque              aper.OpaqueOpenType
	isOpaque            bool
	rowERABAdmittedItem *ERABAdmittedItem
}

func (v ERABAdmittedItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(20):
		return v.rowERABAdmittedItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABAdmittedItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABAdmittedItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABAdmittedItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedItemIEs"}}
}
func (ERABAdmittedItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(20):
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

// AsERABAdmittedItem returns the selected ERABAdmittedItem value of ERABAdmittedItemIEValue and reports whether that alternative is active.
func (v *ERABAdmittedItemIEValue) AsERABAdmittedItem() (*ERABAdmittedItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(20) || v.rowERABAdmittedItem == nil {
		return nil, false
	}
	return v.rowERABAdmittedItem, true
}
func (v ERABAdmittedItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABAdmittedItemIEValue, error) {
	out := ERABAdmittedItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(20):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABAdmittedItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABAdmittedItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABAdmittedItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABAdmittedItem = &value
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
func (v ERABAdmittedItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABAdmittedItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(20):
		if v.rowERABAdmittedItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABAdmittedItemIEs.id-E-RABAdmittedItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABAdmittedItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABAdmittedItemIEValue:", v.id)
	}
}

type ERABDataForwardingItemIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABDataForwardingItem *ERABDataForwardingItem
}

func (v ERABDataForwardingItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(14):
		return v.rowERABDataForwardingItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABDataForwardingItemIEValue and reports whether the opaque alternative is selected.
func (v *ERABDataForwardingItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABDataForwardingItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABDataForwardingItemIEs"}}
}
func (ERABDataForwardingItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(14):
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

// AsERABDataForwardingItem returns the selected ERABDataForwardingItem value of ERABDataForwardingItemIEValue and reports whether that alternative is active.
func (v *ERABDataForwardingItemIEValue) AsERABDataForwardingItem() (*ERABDataForwardingItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(14) || v.rowERABDataForwardingItem == nil {
		return nil, false
	}
	return v.rowERABDataForwardingItem, true
}
func (v ERABDataForwardingItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABDataForwardingItemIEValue, error) {
	out := ERABDataForwardingItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(14):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABDataForwardingItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABDataForwardingItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABDataForwardingItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABDataForwardingItem = &value
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
func (v ERABDataForwardingItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABDataForwardingItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(14):
		if v.rowERABDataForwardingItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABDataForwardingItemIEs.id-E-RABDataForwardingItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABDataForwardingItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABDataForwardingItemIEValue:", v.id)
	}
}

type ERABFailedToResumeItemResumeReqIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowERABFailedToResumeItemResumeReq *ERABFailedToResumeItemResumeReq
}

func (v ERABFailedToResumeItemResumeReqIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(236):
		return v.rowERABFailedToResumeItemResumeReq != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABFailedToResumeItemResumeReqIEValue and reports whether the opaque alternative is selected.
func (v *ERABFailedToResumeItemResumeReqIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABFailedToResumeItemResumeReqIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeReqIEs"}}
}
func (ERABFailedToResumeItemResumeReqIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(236):
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

// AsERABFailedToResumeItemResumeReq returns the selected ERABFailedToResumeItemResumeReq value of ERABFailedToResumeItemResumeReqIEValue and reports whether that alternative is active.
func (v *ERABFailedToResumeItemResumeReqIEValue) AsERABFailedToResumeItemResumeReq() (*ERABFailedToResumeItemResumeReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(236) || v.rowERABFailedToResumeItemResumeReq == nil {
		return nil, false
	}
	return v.rowERABFailedToResumeItemResumeReq, true
}
func (v ERABFailedToResumeItemResumeReqIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABFailedToResumeItemResumeReqIEValue, error) {
	out := ERABFailedToResumeItemResumeReqIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(236):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABFailedToResumeItemResumeReq
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToResumeItemResumeReq:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABFailedToResumeItemResumeReq")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABFailedToResumeItemResumeReq = &value
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
func (v ERABFailedToResumeItemResumeReqIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABFailedToResumeItemResumeReqIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(236):
		if v.rowERABFailedToResumeItemResumeReq == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABFailedToResumeItemResumeReqIEs.id-E-RABFailedToResumeItemResumeReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABFailedToResumeItemResumeReq.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABFailedToResumeItemResumeReqIEValue:", v.id)
	}
}

type ERABFailedToResumeItemResumeResIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowERABFailedToResumeItemResumeRes *ERABFailedToResumeItemResumeRes
}

func (v ERABFailedToResumeItemResumeResIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(238):
		return v.rowERABFailedToResumeItemResumeRes != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABFailedToResumeItemResumeResIEValue and reports whether the opaque alternative is selected.
func (v *ERABFailedToResumeItemResumeResIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABFailedToResumeItemResumeResIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeResIEs"}}
}
func (ERABFailedToResumeItemResumeResIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(238):
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

// AsERABFailedToResumeItemResumeRes returns the selected ERABFailedToResumeItemResumeRes value of ERABFailedToResumeItemResumeResIEValue and reports whether that alternative is active.
func (v *ERABFailedToResumeItemResumeResIEValue) AsERABFailedToResumeItemResumeRes() (*ERABFailedToResumeItemResumeRes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(238) || v.rowERABFailedToResumeItemResumeRes == nil {
		return nil, false
	}
	return v.rowERABFailedToResumeItemResumeRes, true
}
func (v ERABFailedToResumeItemResumeResIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABFailedToResumeItemResumeResIEValue, error) {
	out := ERABFailedToResumeItemResumeResIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(238):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABFailedToResumeItemResumeRes
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToResumeItemResumeRes:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABFailedToResumeItemResumeRes")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABFailedToResumeItemResumeRes = &value
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
func (v ERABFailedToResumeItemResumeResIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABFailedToResumeItemResumeResIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(238):
		if v.rowERABFailedToResumeItemResumeRes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABFailedToResumeItemResumeResIEs.id-E-RABFailedToResumeItemResumeRes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABFailedToResumeItemResumeRes.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABFailedToResumeItemResumeResIEValue:", v.id)
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
		decode: func(data []byte, options aper.DecodeState) (s14.BearersSubjectToEarlyStatusTransferItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.BearersSubjectToEarlyStatusTransferItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToEarlyStatusTransferItem")
			var zero BearersSubjectToEarlyStatusTransferItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(322), raw)
			if err != nil {
				var empty s14.BearersSubjectToEarlyStatusTransferItem
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItem")
			}
			value, ok := decoded.AsBearersSubjectToEarlyStatusTransferItem()
			if !ok {
				var empty s14.BearersSubjectToEarlyStatusTransferItem
				return empty, fmt.Errorf("binding Bearers-SubjectToEarlyStatusTransfer-ItemIEs.id-Bearers-SubjectToEarlyStatusTransfer-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value s14.BearersSubjectToEarlyStatusTransferItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToEarlyStatusTransferItemIEValue{id: s00.ProtocolIEID(322), rowBearersSubjectToEarlyStatusTransferItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s14.BearersSubjectToEarlyStatusTransferItem, options aper.DecodeState) (s14.BearersSubjectToEarlyStatusTransferItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s14.BearersSubjectToEarlyStatusTransferItem, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APBearersSubjectToEarlyStatusTransferItem(&v, &s)
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
	}, inject: func(value s14.BearersSubjectToEarlyStatusTransferItem) BearersSubjectToEarlyStatusTransferItemIEValue {
		return BearersSubjectToEarlyStatusTransferItemIEValue{id: s00.ProtocolIEID(322), rowBearersSubjectToEarlyStatusTransferItem: &value}
	}, get: func(value *BearersSubjectToEarlyStatusTransferItemIEValue) (*s14.BearersSubjectToEarlyStatusTransferItem, bool) {
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

type ERABAdmittedItemIETable struct{}

func ERABAdmittedItemIEs() ERABAdmittedItemIETable { return ERABAdmittedItemIETable{} }

// ID returns the ASN.1 object-set identity of ERABAdmittedItemIETable.
func (ERABAdmittedItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABAdmittedItemIETable.
func (ERABAdmittedItemIETable) Table() s00.ERABAdmittedItemIEValueIETable {
	return func() s00.ERABAdmittedItemIEValueIETable {
		sealed := s00.ERABAdmittedItemIEValueIETable{}
		*s00.BridgeERABAdmittedItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABAdmittedItemIETable) infoERABAdmittedItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABAdmittedItemIEs().ID(), ID: s00.ProtocolIEID(20), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABAdmittedItemIEs", Row: "id-E-RABAdmittedItem"}}}
}

// ERABAdmittedItem returns the typed binding for the ERABAdmittedItem row of ERABAdmittedItemIETable.
func (t ERABAdmittedItemIETable) ERABAdmittedItem() ERABAdmittedItemERABAdmittedItemIEBinding {
	return ERABAdmittedItemERABAdmittedItemIEBinding{info: t.infoERABAdmittedItem(), codec: ERABAdmittedItemValueCodec{path: "ERABAdmittedItem",
		decode: func(data []byte, options aper.DecodeState) (ERABAdmittedItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABAdmittedItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABAdmittedItem")
			var zero ERABAdmittedItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(20), raw)
			if err != nil {
				var empty ERABAdmittedItem
				return empty, runtime.WrapDecodePath(err, "ERABAdmittedItem")
			}
			value, ok := decoded.AsERABAdmittedItem()
			if !ok {
				var empty ERABAdmittedItem
				return empty, fmt.Errorf("binding E-RABAdmittedItemIEs.id-E-RABAdmittedItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABAdmittedItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABAdmittedItemIEValue{id: s00.ProtocolIEID(20), rowERABAdmittedItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABAdmittedItem, options aper.DecodeState) (ERABAdmittedItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			BridgeCaptureS1APERABAdmittedItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABAdmittedItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABAdmittedItem(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABAdmittedItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABAdmittedItem) ERABAdmittedItemIEValue {
		return ERABAdmittedItemIEValue{id: s00.ProtocolIEID(20), rowERABAdmittedItem: &value}
	}, get: func(value *ERABAdmittedItemIEValue) (*ERABAdmittedItem, bool) { return value.AsERABAdmittedItem() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABAdmittedItemIETable.
func (t ERABAdmittedItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABAdmittedItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABAdmittedItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(20):
		return ERABAdmittedItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABAdmittedItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABAdmittedItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABAdmittedItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABAdmittedItemIEField{Id: id, Criticality: criticality, Value: ERABAdmittedItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABDataForwardingItemIETable struct{}

func ERABDataForwardingItemIEs() ERABDataForwardingItemIETable {
	return ERABDataForwardingItemIETable{}
}

// ID returns the ASN.1 object-set identity of ERABDataForwardingItemIETable.
func (ERABDataForwardingItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABDataForwardingItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABDataForwardingItemIETable.
func (ERABDataForwardingItemIETable) Table() s00.ERABDataForwardingItemIEValueIETable {
	return func() s00.ERABDataForwardingItemIEValueIETable {
		sealed := s00.ERABDataForwardingItemIEValueIETable{}
		*s00.BridgeERABDataForwardingItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABDataForwardingItemIETable) infoERABDataForwardingItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABDataForwardingItemIEs().ID(), ID: s00.ProtocolIEID(14), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABDataForwardingItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABDataForwardingItemIEs", Row: "id-E-RABDataForwardingItem"}}}
}

// ERABDataForwardingItem returns the typed binding for the ERABDataForwardingItem row of ERABDataForwardingItemIETable.
func (t ERABDataForwardingItemIETable) ERABDataForwardingItem() ERABDataForwardingItemERABDataForwardingItemIEBinding {
	return ERABDataForwardingItemERABDataForwardingItemIEBinding{info: t.infoERABDataForwardingItem(), codec: ERABDataForwardingItemValueCodec{path: "ERABDataForwardingItem",
		decode: func(data []byte, options aper.DecodeState) (ERABDataForwardingItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABDataForwardingItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABDataForwardingItem")
			var zero ERABDataForwardingItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(14), raw)
			if err != nil {
				var empty ERABDataForwardingItem
				return empty, runtime.WrapDecodePath(err, "ERABDataForwardingItem")
			}
			value, ok := decoded.AsERABDataForwardingItem()
			if !ok {
				var empty ERABDataForwardingItem
				return empty, fmt.Errorf("binding E-RABDataForwardingItemIEs.id-E-RABDataForwardingItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABDataForwardingItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABDataForwardingItemIEValue{id: s00.ProtocolIEID(14), rowERABDataForwardingItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABDataForwardingItem, options aper.DecodeState) (ERABDataForwardingItem, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABDataForwardingItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABDataForwardingItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABDataForwardingItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABDataForwardingItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABDataForwardingItem) ERABDataForwardingItemIEValue {
		return ERABDataForwardingItemIEValue{id: s00.ProtocolIEID(14), rowERABDataForwardingItem: &value}
	}, get: func(value *ERABDataForwardingItemIEValue) (*ERABDataForwardingItem, bool) {
		return value.AsERABDataForwardingItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABDataForwardingItemIETable.
func (t ERABDataForwardingItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABDataForwardingItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABDataForwardingItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(14):
		return ERABDataForwardingItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABDataForwardingItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABDataForwardingItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABDataForwardingItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABDataForwardingItemIEField{Id: id, Criticality: criticality, Value: ERABDataForwardingItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABFailedToResumeItemResumeReqIETable struct{}

func ERABFailedToResumeItemResumeReqIEs() ERABFailedToResumeItemResumeReqIETable {
	return ERABFailedToResumeItemResumeReqIETable{}
}

// ID returns the ASN.1 object-set identity of ERABFailedToResumeItemResumeReqIETable.
func (ERABFailedToResumeItemResumeReqIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeReqIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ERABFailedToResumeItemResumeReqIETable.
func (ERABFailedToResumeItemResumeReqIETable) Table() s00.ERABFailedToResumeItemResumeReqIEValueIETable {
	return func() s00.ERABFailedToResumeItemResumeReqIEValueIETable {
		sealed := s00.ERABFailedToResumeItemResumeReqIEValueIETable{}
		*s00.BridgeERABFailedToResumeItemResumeReqIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABFailedToResumeItemResumeReqIETable) infoERABFailedToResumeItemResumeReq() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABFailedToResumeItemResumeReqIEs().ID(), ID: s00.ProtocolIEID(236), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeItemResumeReqIEs", Row: "id-E-RABFailedToResumeItemResumeReq"}}}
}

// ERABFailedToResumeItemResumeReq returns the typed binding for the ERABFailedToResumeItemResumeReq row of ERABFailedToResumeItemResumeReqIETable.
func (t ERABFailedToResumeItemResumeReqIETable) ERABFailedToResumeItemResumeReq() ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding {
	return ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding{info: t.infoERABFailedToResumeItemResumeReq(), codec: ERABFailedToResumeItemResumeReqValueCodec{path: "ERABFailedToResumeItemResumeReq",
		decode: func(data []byte, options aper.DecodeState) (ERABFailedToResumeItemResumeReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABFailedToResumeItemResumeReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABFailedToResumeItemResumeReq")
			var zero ERABFailedToResumeItemResumeReqIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(236), raw)
			if err != nil {
				var empty ERABFailedToResumeItemResumeReq
				return empty, runtime.WrapDecodePath(err, "ERABFailedToResumeItemResumeReq")
			}
			value, ok := decoded.AsERABFailedToResumeItemResumeReq()
			if !ok {
				var empty ERABFailedToResumeItemResumeReq
				return empty, fmt.Errorf("binding E-RABFailedToResumeItemResumeReqIEs.id-E-RABFailedToResumeItemResumeReq: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABFailedToResumeItemResumeReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABFailedToResumeItemResumeReqIEValue{id: s00.ProtocolIEID(236), rowERABFailedToResumeItemResumeReq: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABFailedToResumeItemResumeReq, options aper.DecodeState) (ERABFailedToResumeItemResumeReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABFailedToResumeItemResumeReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABFailedToResumeItemResumeReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABFailedToResumeItemResumeReq(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABFailedToResumeItemResumeReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABFailedToResumeItemResumeReq) ERABFailedToResumeItemResumeReqIEValue {
		return ERABFailedToResumeItemResumeReqIEValue{id: s00.ProtocolIEID(236), rowERABFailedToResumeItemResumeReq: &value}
	}, get: func(value *ERABFailedToResumeItemResumeReqIEValue) (*ERABFailedToResumeItemResumeReq, bool) {
		return value.AsERABFailedToResumeItemResumeReq()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ERABFailedToResumeItemResumeReqIETable.
func (t ERABFailedToResumeItemResumeReqIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABFailedToResumeItemResumeReqIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(236):
		return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToResumeItemResumeReq requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABFailedToResumeItemResumeReqIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABFailedToResumeItemResumeReqIEField{Id: id, Criticality: criticality, Value: ERABFailedToResumeItemResumeReqIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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

// DLCOUNTPDCPSNlengthCodec binds the complete source value type.
func DLCOUNTPDCPSNlengthCodec() DLCOUNTPDCPSNlengthValueCodec {
	return DLCOUNTPDCPSNlengthValueCodec{path: "DLCOUNTPDCPSNlength", decode: func(data []byte, options aper.DecodeState) (s14.DLCOUNTPDCPSNlength, error) {
		var value s14.DLCOUNTPDCPSNlength
		if err := s14.BridgeDLCOUNTPDCPSNlengthMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s14.DLCOUNTPDCPSNlength{}, err
		}
		*s14.BridgeDLCOUNTPDCPSNlengthFieldReceived(&value) = true
		*s14.BridgeDLCOUNTPDCPSNlengthFieldReceivedAbsolute(&value) = true
		*s14.BridgeDLCOUNTPDCPSNlengthFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s14.DLCOUNTPDCPSNlength, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s14.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s14.DLCOUNTPDCPSNlength, options aper.DecodeState) (s14.DLCOUNTPDCPSNlength, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s14.BridgeCaptureS1APDLCOUNTPDCPSNlength(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v s14.DLCOUNTPDCPSNlength, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s14.BridgeCompareS1APDLCOUNTPDCPSNlength(&v, &s)
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

// EHRPDCompositeAvailableCapacityCodec binds the complete source value type.
func EHRPDCompositeAvailableCapacityCodec() EHRPDCompositeAvailableCapacityValueCodec {
	return EHRPDCompositeAvailableCapacityValueCodec{path: "EHRPDCompositeAvailableCapacity", decode: func(data []byte, options aper.DecodeState) (EHRPDCompositeAvailableCapacity, error) {
		var value EHRPDCompositeAvailableCapacity
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EHRPDCompositeAvailableCapacity{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EHRPDCompositeAvailableCapacity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EHRPDCompositeAvailableCapacity, options aper.DecodeState) (EHRPDCompositeAvailableCapacity, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEHRPDCompositeAvailableCapacity(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v EHRPDCompositeAvailableCapacity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEHRPDCompositeAvailableCapacity(&v, &s)

		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDCompositeAvailableCapacity"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EHRPDMultiSectorLoadReportingResponseItemCodec binds the complete source value type.
func EHRPDMultiSectorLoadReportingResponseItemCodec() EHRPDMultiSectorLoadReportingResponseItemValueCodec {
	return EHRPDMultiSectorLoadReportingResponseItemValueCodec{path: "EHRPDMultiSectorLoadReportingResponseItem", decode: func(data []byte, options aper.DecodeState) (EHRPDMultiSectorLoadReportingResponseItem, error) {
		var value EHRPDMultiSectorLoadReportingResponseItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EHRPDMultiSectorLoadReportingResponseItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EHRPDMultiSectorLoadReportingResponseItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EHRPDMultiSectorLoadReportingResponseItem, options aper.DecodeState) (EHRPDMultiSectorLoadReportingResponseItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEHRPDMultiSectorLoadReportingResponseItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v EHRPDMultiSectorLoadReportingResponseItem, root aper.Snapshot, budget aper.DecodeBudget,
	) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDMultiSectorLoadReportingResponseItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EHRPDSectorLoadReportingResponseCodec binds the complete source value type.
func EHRPDSectorLoadReportingResponseCodec() EHRPDSectorLoadReportingResponseValueCodec {
	return EHRPDSectorLoadReportingResponseValueCodec{path: "EHRPDSectorLoadReportingResponse", decode: func(data []byte, options aper.DecodeState) (EHRPDSectorLoadReportingResponse, error) {
		var value EHRPDSectorLoadReportingResponse
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EHRPDSectorLoadReportingResponse{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EHRPDSectorLoadReportingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EHRPDSectorLoadReportingResponse, options aper.DecodeState) (EHRPDSectorLoadReportingResponse, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEHRPDSectorLoadReportingResponse(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v EHRPDSectorLoadReportingResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEHRPDSectorLoadReportingResponse(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDSectorLoadReportingResponse"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENBIDCodec binds the complete source value type.
func ENBIDCodec() ENBIDValueCodec {
	return ENBIDValueCodec{path: "ENBID", decode: func(data []byte, options aper.DecodeState) (ENBID, error) {
		var value ENBID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENBID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENBID, options aper.DecodeState) (ENBID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENBID(&v, &s)
		var root aper.Snapshot
		s.End(f,
			&root, false)
		return v, root
	}, compare: func(v ENBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENBID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENBX2ExtTLACodec binds the complete source value type.
func ENBX2ExtTLACodec() ENBX2ExtTLAValueCodec {
	return ENBX2ExtTLAValueCodec{path: "ENBX2ExtTLA", decode: func(data []byte, options aper.DecodeState) (ENBX2ExtTLA, error) {
		var value ENBX2ExtTLA
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ENBX2ExtTLA{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ENBX2ExtTLA, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ENBX2ExtTLA, options aper.DecodeState) (ENBX2ExtTLA, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APENBX2ExtTLA(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBX2ExtTLA, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APENBX2ExtTLA(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBX2ExtTLA"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ERABAdmittedItemCodec binds the complete APER value type.
func ERABAdmittedItemCodec() ERABAdmittedItemValueCodec {
	return ERABAdmittedItemIEs().ERABAdmittedItem().Codec()
}

// ERABDataForwardingItemCodec binds the complete APER value type.
func ERABDataForwardingItemCodec() ERABDataForwardingItemValueCodec {
	return ERABDataForwardingItemIEs().ERABDataForwardingItem().Codec()
}

// ERABFailedToResumeItemResumeReqCodec binds the complete APER value type.
func ERABFailedToResumeItemResumeReqCodec() ERABFailedToResumeItemResumeReqValueCodec {
	return ERABFailedToResumeItemResumeReqIEs().ERABFailedToResumeItemResumeReq().Codec()
}
func BridgeBearersSubjectToDLDiscardingItemAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBindingFieldCodec(v *BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) *BearersSubjectToDLDiscardingItemValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBindingFieldGet(v *BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) *func(*BearersSubjectToDLDiscardingItemIEValue) (*BearersSubjectToDLDiscardingItem, bool) {
	return &v.get
}
func BridgeBearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBindingFieldInfo(v *BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeBearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBindingFieldInject(v *BearersSubjectToDLDiscardingItemBearersSubjectToDLDiscardingItemIEBinding) *func(BearersSubjectToDLDiscardingItem) BearersSubjectToDLDiscardingItemIEValue {
	return &v.inject
}
func BridgeBearersSubjectToDLDiscardingItemFieldExtCount(v *BearersSubjectToDLDiscardingItem) *int64 {
	return &v.extCount
}
func BridgeBearersSubjectToDLDiscardingItemFieldExtData(v *BearersSubjectToDLDiscardingItem) *[][]byte {
	return &v.extData
}
func BridgeBearersSubjectToDLDiscardingItemFieldExtOrigin(v *BearersSubjectToDLDiscardingItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeBearersSubjectToDLDiscardingItemFieldExtPresent(v *BearersSubjectToDLDiscardingItem) *[]bool {
	return &v.extPresent
}
func BridgeBearersSubjectToDLDiscardingItemFieldExtWire(v *BearersSubjectToDLDiscardingItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeBearersSubjectToDLDiscardingItemFieldIEExtensionsIndef(v *BearersSubjectToDLDiscardingItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeBearersSubjectToDLDiscardingItemFieldPerExtPadding(v *BearersSubjectToDLDiscardingItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeBearersSubjectToDLDiscardingItemFieldPerPadding(v *BearersSubjectToDLDiscardingItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeBearersSubjectToDLDiscardingItemFieldReceived(v *BearersSubjectToDLDiscardingItem) *bool {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemFieldReceivedAbsolute(v *BearersSubjectToDLDiscardingItem) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToDLDiscardingItemFieldReceivedBytes(v *BearersSubjectToDLDiscardingItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToDLDiscardingItemFieldReceivedLocation(v *BearersSubjectToDLDiscardingItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToDLDiscardingItemFieldReplay(v *BearersSubjectToDLDiscardingItem) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemFieldStream(v *BearersSubjectToDLDiscardingItem) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToDLDiscardingItemFieldWithoutReplay(v *BearersSubjectToDLDiscardingItem) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemIEContainerValueCodec, a0 BearersSubjectToDLDiscardingItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemIEContainerValueCodec, a0 BearersSubjectToDLDiscardingItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReceived(v *BearersSubjectToDLDiscardingItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v *BearersSubjectToDLDiscardingItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldFieldStream(v *BearersSubjectToDLDiscardingItemIEField) *aper.WireSpan {
	return &v.stream
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
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemIEFieldValueCodec, a0 BearersSubjectToDLDiscardingItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemIEFieldValueCodec, a0 BearersSubjectToDLDiscardingItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToDLDiscardingItemIETableMethodInfoBearersSubjectToDLDiscardingItem(v BearersSubjectToDLDiscardingItemIETable) s00.FieldInfo {
	return v.infoBearersSubjectToDLDiscardingItem()
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEValue) *aper.Snapshot {
	return &v.replay
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
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodDecode(v BearersSubjectToDLDiscardingItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToDLDiscardingItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodEncode(v BearersSubjectToDLDiscardingItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodEncodeFresh(v BearersSubjectToDLDiscardingItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodMatchesID(v BearersSubjectToDLDiscardingItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodReason(v BearersSubjectToDLDiscardingItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueMethodRule(v BearersSubjectToDLDiscardingItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValueFieldContext(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERBudget(v *BearersSubjectToDLDiscardingItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERBudgetValue(v *BearersSubjectToDLDiscardingItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERChanged(v *BearersSubjectToDLDiscardingItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERChangedValue(v *BearersSubjectToDLDiscardingItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERLegacy(v *BearersSubjectToDLDiscardingItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERNewValue(v *BearersSubjectToDLDiscardingItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERPlanned(v *BearersSubjectToDLDiscardingItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemMethodMarshalAPERTo(v *BearersSubjectToDLDiscardingItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemMethodUnmarshalAPERFrom(v *BearersSubjectToDLDiscardingItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToDLDiscardingItemMethodUnmarshalAPERLegacy(v *BearersSubjectToDLDiscardingItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToDLDiscardingItemMethodUnmarshalAPERWithOptions(v *BearersSubjectToDLDiscardingItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldCapture(v *BearersSubjectToDLDiscardingItemValueCodec) *func(BearersSubjectToDLDiscardingItem, aper.DecodeState) (BearersSubjectToDLDiscardingItem, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldCompare(v *BearersSubjectToDLDiscardingItemValueCodec) *func(BearersSubjectToDLDiscardingItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldContext(v *BearersSubjectToDLDiscardingItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldDecode(v *BearersSubjectToDLDiscardingItemValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToDLDiscardingItem, error) {
	return &v.decode
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldEncode(v *BearersSubjectToDLDiscardingItemValueCodec) *func(BearersSubjectToDLDiscardingItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecFieldPath(v *BearersSubjectToDLDiscardingItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingItemValueCodec, a0 BearersSubjectToDLDiscardingItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingItemValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingItemValueCodec, a0 BearersSubjectToDLDiscardingItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToDLDiscardingListAPERValueFieldContext(v *BearersSubjectToDLDiscardingListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToDLDiscardingListAPERValueFieldReceived(v *BearersSubjectToDLDiscardingListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingListAPERValueFieldReplay(v *BearersSubjectToDLDiscardingListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingListAPERValueFieldWithoutReplay(v *BearersSubjectToDLDiscardingListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToDLDiscardingListValueCodecMethodEncodeBudgetValue(v BearersSubjectToDLDiscardingListValueCodec, a0 BearersSubjectToDLDiscardingList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListValueCodecMethodEncodeChanged(v BearersSubjectToDLDiscardingListValueCodec, a0 BearersSubjectToDLDiscardingList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBindingFieldCodec(v *BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) *BearersSubjectToEarlyStatusTransferItemValueCodec {
	return &v.codec
}
func BridgeBearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBindingFieldGet(v *BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) *func(*BearersSubjectToEarlyStatusTransferItemIEValue) (*s14.BearersSubjectToEarlyStatusTransferItem, bool) {
	return &v.get
}
func BridgeBearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBindingFieldInfo(v *BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeBearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBindingFieldInject(v *BearersSubjectToEarlyStatusTransferItemBearersSubjectToEarlyStatusTransferItemIEBinding) *func(s14.BearersSubjectToEarlyStatusTransferItem) BearersSubjectToEarlyStatusTransferItemIEValue {
	return &v.inject
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldStream(v *BearersSubjectToEarlyStatusTransferItemIEField) *aper.WireSpan {
	return &v.stream
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIETableMethodInfoBearersSubjectToEarlyStatusTransferItem(v BearersSubjectToEarlyStatusTransferItemIETable) s00.FieldInfo {
	return v.infoBearersSubjectToEarlyStatusTransferItem()
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueFieldRowBearersSubjectToEarlyStatusTransferItem(v *BearersSubjectToEarlyStatusTransferItemIEValue) **s14.BearersSubjectToEarlyStatusTransferItem {
	return &v.rowBearersSubjectToEarlyStatusTransferItem
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCaptureSemantics(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 aper.SemanticCapture) BearersSubjectToEarlyStatusTransferItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCompareSemantics(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodDecode(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToEarlyStatusTransferItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodEncode(v BearersSubjectToEarlyStatusTransferItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodEncodeFresh(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodMatchesID(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodReason(v BearersSubjectToEarlyStatusTransferItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodRule(v BearersSubjectToEarlyStatusTransferItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec, a0 BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldCapture(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *func(s14.BearersSubjectToEarlyStatusTransferItem, aper.DecodeState) (s14.BearersSubjectToEarlyStatusTransferItem, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldCompare(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *func(s14.BearersSubjectToEarlyStatusTransferItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldContext(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldDecode(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *func([]byte, aper.DecodeState) (s14.BearersSubjectToEarlyStatusTransferItem, error) {
	return &v.decode
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldEncode(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *func(s14.BearersSubjectToEarlyStatusTransferItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecFieldPath(v *BearersSubjectToEarlyStatusTransferItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferItemValueCodec, a0 s14.BearersSubjectToEarlyStatusTransferItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferItemValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferItemValueCodec, a0 s14.BearersSubjectToEarlyStatusTransferItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBearersSubjectToEarlyStatusTransferListAPERValueFieldContext(v *BearersSubjectToEarlyStatusTransferListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToEarlyStatusTransferListAPERValueFieldReceived(v *BearersSubjectToEarlyStatusTransferListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferListAPERValueFieldReplay(v *BearersSubjectToEarlyStatusTransferListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferListAPERValueFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecMethodEncodeBudgetValue(v BearersSubjectToEarlyStatusTransferListValueCodec, a0 BearersSubjectToEarlyStatusTransferList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferListValueCodecMethodEncodeChanged(v BearersSubjectToEarlyStatusTransferListValueCodec, a0 BearersSubjectToEarlyStatusTransferList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDLCOUNTPDCPSNlengthAPERValueFieldContext(v *DLCOUNTPDCPSNlengthAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCOUNTPDCPSNlengthAPERValueFieldReceived(v *DLCOUNTPDCPSNlengthAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDLCOUNTPDCPSNlengthAPERValueFieldReplay(v *DLCOUNTPDCPSNlengthAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDLCOUNTPDCPSNlengthAPERValueFieldWithoutReplay(v *DLCOUNTPDCPSNlengthAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldCapture(v *DLCOUNTPDCPSNlengthValueCodec) *func(s14.DLCOUNTPDCPSNlength, aper.DecodeState) (s14.DLCOUNTPDCPSNlength, aper.Snapshot) {
	return &v.capture
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldCompare(v *DLCOUNTPDCPSNlengthValueCodec) *func(s14.DLCOUNTPDCPSNlength, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldContext(v *DLCOUNTPDCPSNlengthValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldDecode(v *DLCOUNTPDCPSNlengthValueCodec) *func([]byte, aper.DecodeState) (s14.DLCOUNTPDCPSNlength, error) {
	return &v.decode
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldEncode(v *DLCOUNTPDCPSNlengthValueCodec) *func(s14.DLCOUNTPDCPSNlength, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLCOUNTPDCPSNlengthValueCodecFieldPath(v *DLCOUNTPDCPSNlengthValueCodec) *aper.Path {
	return &v.path
}
func BridgeDLCOUNTPDCPSNlengthValueCodecMethodEncodeBudgetValue(v DLCOUNTPDCPSNlengthValueCodec, a0 s14.DLCOUNTPDCPSNlength, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDLCOUNTPDCPSNlengthValueCodecMethodEncodeChanged(v DLCOUNTPDCPSNlengthValueCodec, a0 s14.DLCOUNTPDCPSNlength, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDLCPSecurityInformationAPERValueFieldContext(v *DLCPSecurityInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLCPSecurityInformationAPERValueFieldReceived(v *DLCPSecurityInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDLCPSecurityInformationAPERValueFieldReplay(v *DLCPSecurityInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDLCPSecurityInformationAPERValueFieldWithoutReplay(v *DLCPSecurityInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDLCPSecurityInformationFieldExtCount(v *DLCPSecurityInformation) *int64 {
	return &v.extCount
}
func BridgeDLCPSecurityInformationFieldExtData(v *DLCPSecurityInformation) *[][]byte {
	return &v.extData
}
func BridgeDLCPSecurityInformationFieldExtOrigin(v *DLCPSecurityInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDLCPSecurityInformationFieldExtPresent(v *DLCPSecurityInformation) *[]bool {
	return &v.extPresent
}
func BridgeDLCPSecurityInformationFieldExtWire(v *DLCPSecurityInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDLCPSecurityInformationFieldIEExtensionsIndef(v *DLCPSecurityInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeDLCPSecurityInformationFieldPerExtPadding(v *DLCPSecurityInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDLCPSecurityInformationFieldPerPadding(v *DLCPSecurityInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDLCPSecurityInformationFieldReceived(v *DLCPSecurityInformation) *bool { return &v.received }
func BridgeDLCPSecurityInformationFieldReceivedAbsolute(v *DLCPSecurityInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeDLCPSecurityInformationFieldReceivedBytes(v *DLCPSecurityInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDLCPSecurityInformationFieldReceivedLocation(v *DLCPSecurityInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeDLCPSecurityInformationFieldReplay(v *DLCPSecurityInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeDLCPSecurityInformationFieldStream(v *DLCPSecurityInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeDLCPSecurityInformationFieldWithoutReplay(v *DLCPSecurityInformation) *bool {
	return &v.withoutReplay
}
func BridgeDLCPSecurityInformationMethodMarshalAPERBudget(v *DLCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERBudgetValue(v *DLCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERChanged(v *DLCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERChangedValue(v *DLCPSecurityInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERLegacy(v *DLCPSecurityInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDLCPSecurityInformationMethodMarshalAPERNewValue(v *DLCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERPlanned(v *DLCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDLCPSecurityInformationMethodMarshalAPERTo(v *DLCPSecurityInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDLCPSecurityInformationMethodUnmarshalAPERFrom(v *DLCPSecurityInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDLCPSecurityInformationMethodUnmarshalAPERLegacy(v *DLCPSecurityInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDLCPSecurityInformationMethodUnmarshalAPERWithOptions(v *DLCPSecurityInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeDLCPSecurityInformationValueCodecMethodEncodeBudgetValue(v DLCPSecurityInformationValueCodec, a0 DLCPSecurityInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDLCPSecurityInformationValueCodecMethodEncodeChanged(v DLCPSecurityInformationValueCodec, a0 DLCPSecurityInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDLDiscardingAPERValueFieldContext(v *DLDiscardingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLDiscardingAPERValueFieldReceived(v *DLDiscardingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDLDiscardingAPERValueFieldReplay(v *DLDiscardingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDLDiscardingAPERValueFieldWithoutReplay(v *DLDiscardingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDLDiscardingFieldPerOpenTypePadding(v *DLDiscarding) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeDLDiscardingFieldPerPadding(v *DLDiscarding) *aper.CompletePadding { return &v.perPadding }
func BridgeDLDiscardingFieldReceived(v *DLDiscarding) *bool                   { return &v.received }
func BridgeDLDiscardingFieldReceivedAbsolute(v *DLDiscarding) *bool           { return &v.receivedAbsolute }
func BridgeDLDiscardingFieldReceivedBytes(v *DLDiscarding) *aper.WireSpan     { return &v.receivedBytes }
func BridgeDLDiscardingFieldReceivedLocation(v *DLDiscarding) *aper.Location {
	return &v.receivedLocation
}
func BridgeDLDiscardingFieldReplay(v *DLDiscarding) *aper.Snapshot { return &v.replay }
func BridgeDLDiscardingFieldStream(v *DLDiscarding) *aper.WireSpan { return &v.stream }
func BridgeDLDiscardingFieldWithoutReplay(v *DLDiscarding) *bool   { return &v.withoutReplay }
func BridgeDLDiscardingMethodMarshalAPERBudget(v *DLDiscarding, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDLDiscardingMethodMarshalAPERBudgetValue(v *DLDiscarding, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDLDiscardingMethodMarshalAPERChanged(v *DLDiscarding, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDLDiscardingMethodMarshalAPERChangedValue(v *DLDiscarding, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDLDiscardingMethodMarshalAPERLegacy(v *DLDiscarding) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDLDiscardingMethodMarshalAPERNewValue(v *DLDiscarding, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDLDiscardingMethodMarshalAPERPlanned(v *DLDiscarding, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDLDiscardingMethodMarshalAPERTo(v *DLDiscarding, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDLDiscardingMethodUnmarshalAPERFrom(v *DLDiscarding, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDLDiscardingMethodUnmarshalAPERLegacy(v *DLDiscarding, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDLDiscardingMethodUnmarshalAPERWithOptions(v *DLDiscarding, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDLDiscardingValueCodecFieldCapture(v *DLDiscardingValueCodec) *func(DLDiscarding, aper.DecodeState) (DLDiscarding, aper.Snapshot) {
	return &v.capture
}
func BridgeDLDiscardingValueCodecFieldCompare(v *DLDiscardingValueCodec) *func(DLDiscarding, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDLDiscardingValueCodecFieldContext(v *DLDiscardingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDLDiscardingValueCodecFieldDecode(v *DLDiscardingValueCodec) *func([]byte, aper.DecodeState) (DLDiscarding, error) {
	return &v.decode
}
func BridgeDLDiscardingValueCodecFieldEncode(v *DLDiscardingValueCodec) *func(DLDiscarding, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLDiscardingValueCodecFieldPath(v *DLDiscardingValueCodec) *aper.Path { return &v.path }
func BridgeDLDiscardingValueCodecMethodEncodeBudgetValue(v DLDiscardingValueCodec, a0 DLDiscarding, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDLDiscardingValueCodecMethodEncodeChanged(v DLDiscardingValueCodec, a0 DLDiscarding, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDeactivateTraceAPERValueFieldContext(v *DeactivateTraceAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceAPERValueFieldReceived(v *DeactivateTraceAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDeactivateTraceAPERValueFieldReplay(v *DeactivateTraceAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDeactivateTraceAPERValueFieldWithoutReplay(v *DeactivateTraceAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDeactivateTraceFieldExtCount(v *DeactivateTrace) *int64   { return &v.extCount }
func BridgeDeactivateTraceFieldExtData(v *DeactivateTrace) *[][]byte { return &v.extData }
func BridgeDeactivateTraceFieldExtOrigin(v *DeactivateTrace) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDeactivateTraceFieldExtPresent(v *DeactivateTrace) *[]bool       { return &v.extPresent }
func BridgeDeactivateTraceFieldExtWire(v *DeactivateTrace) *[]aper.WireSpan { return &v.extWire }
func BridgeDeactivateTraceFieldPerExtPadding(v *DeactivateTrace) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDeactivateTraceFieldPerPadding(v *DeactivateTrace) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDeactivateTraceFieldProtocolIEsIndef(v *DeactivateTrace) *bool { return &v.protocolIEsIndef }
func BridgeDeactivateTraceFieldReceived(v *DeactivateTrace) *bool         { return &v.received }
func BridgeDeactivateTraceFieldReceivedAbsolute(v *DeactivateTrace) *bool { return &v.receivedAbsolute }
func BridgeDeactivateTraceFieldReceivedBytes(v *DeactivateTrace) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDeactivateTraceFieldReceivedLocation(v *DeactivateTrace) *aper.Location {
	return &v.receivedLocation
}
func BridgeDeactivateTraceFieldReplay(v *DeactivateTrace) *aper.Snapshot { return &v.replay }
func BridgeDeactivateTraceFieldStream(v *DeactivateTrace) *aper.WireSpan { return &v.stream }
func BridgeDeactivateTraceFieldWithoutReplay(v *DeactivateTrace) *bool   { return &v.withoutReplay }
func BridgeDeactivateTraceMethodMarshalAPERBudget(v *DeactivateTrace, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDeactivateTraceMethodMarshalAPERBudgetValue(v *DeactivateTrace, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDeactivateTraceMethodMarshalAPERChanged(v *DeactivateTrace, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDeactivateTraceMethodMarshalAPERChangedValue(v *DeactivateTrace, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDeactivateTraceMethodMarshalAPERLegacy(v *DeactivateTrace) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDeactivateTraceMethodMarshalAPERNewValue(v *DeactivateTrace, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDeactivateTraceMethodMarshalAPERPlanned(v *DeactivateTrace, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDeactivateTraceMethodMarshalAPERTo(v *DeactivateTrace, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDeactivateTraceMethodUnmarshalAPERFrom(v *DeactivateTrace, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDeactivateTraceMethodUnmarshalAPERLegacy(v *DeactivateTrace, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDeactivateTraceMethodUnmarshalAPERWithOptions(v *DeactivateTrace, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDeactivateTraceValueCodecFieldCapture(v *DeactivateTraceValueCodec) *func(DeactivateTrace, aper.DecodeState) (DeactivateTrace, aper.Snapshot) {
	return &v.capture
}
func BridgeDeactivateTraceValueCodecFieldCompare(v *DeactivateTraceValueCodec) *func(DeactivateTrace, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDeactivateTraceValueCodecFieldContext(v *DeactivateTraceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDeactivateTraceValueCodecFieldDecode(v *DeactivateTraceValueCodec) *func([]byte, aper.DecodeState) (DeactivateTrace, error) {
	return &v.decode
}
func BridgeDeactivateTraceValueCodecFieldEncode(v *DeactivateTraceValueCodec) *func(DeactivateTrace, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDeactivateTraceValueCodecFieldPath(v *DeactivateTraceValueCodec) *aper.Path {
	return &v.path
}
func BridgeDeactivateTraceValueCodecMethodEncodeBudgetValue(v DeactivateTraceValueCodec, a0 DeactivateTrace, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDeactivateTraceValueCodecMethodEncodeChanged(v DeactivateTraceValueCodec, a0 DeactivateTrace, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportAPERValueFieldContext(v *DownlinkNonUEAssociatedLPPaTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportAPERValueFieldReceived(v *DownlinkNonUEAssociatedLPPaTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNonUEAssociatedLPPaTransportAPERValueFieldReplay(v *DownlinkNonUEAssociatedLPPaTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportAPERValueFieldWithoutReplay(v *DownlinkNonUEAssociatedLPPaTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldExtCount(v *DownlinkNonUEAssociatedLPPaTransport) *int64 {
	return &v.extCount
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldExtData(v *DownlinkNonUEAssociatedLPPaTransport) *[][]byte {
	return &v.extData
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldExtOrigin(v *DownlinkNonUEAssociatedLPPaTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldExtPresent(v *DownlinkNonUEAssociatedLPPaTransport) *[]bool {
	return &v.extPresent
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldExtWire(v *DownlinkNonUEAssociatedLPPaTransport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldPerExtPadding(v *DownlinkNonUEAssociatedLPPaTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldPerPadding(v *DownlinkNonUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldProtocolIEsIndef(v *DownlinkNonUEAssociatedLPPaTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceived(v *DownlinkNonUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(v *DownlinkNonUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedBytes(v *DownlinkNonUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldReceivedLocation(v *DownlinkNonUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldReplay(v *DownlinkNonUEAssociatedLPPaTransport) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldStream(v *DownlinkNonUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.stream
}
func BridgeDownlinkNonUEAssociatedLPPaTransportFieldWithoutReplay(v *DownlinkNonUEAssociatedLPPaTransport) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *DownlinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudgetValue(v *DownlinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERChanged(v *DownlinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERChangedValue(v *DownlinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERLegacy(v *DownlinkNonUEAssociatedLPPaTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERNewValue(v *DownlinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERPlanned(v *DownlinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERTo(v *DownlinkNonUEAssociatedLPPaTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *DownlinkNonUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERLegacy(v *DownlinkNonUEAssociatedLPPaTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *DownlinkNonUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *func(DownlinkNonUEAssociatedLPPaTransport, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *func(DownlinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldContext(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (DownlinkNonUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *func(DownlinkNonUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecFieldPath(v *DownlinkNonUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecMethodEncodeBudgetValue(v DownlinkNonUEAssociatedLPPaTransportValueCodec, a0 DownlinkNonUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNonUEAssociatedLPPaTransportValueCodecMethodEncodeChanged(v DownlinkNonUEAssociatedLPPaTransportValueCodec, a0 DownlinkNonUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkUEAssociatedLPPaTransportAPERValueFieldContext(v *DownlinkUEAssociatedLPPaTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportAPERValueFieldReceived(v *DownlinkUEAssociatedLPPaTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkUEAssociatedLPPaTransportAPERValueFieldReplay(v *DownlinkUEAssociatedLPPaTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkUEAssociatedLPPaTransportAPERValueFieldWithoutReplay(v *DownlinkUEAssociatedLPPaTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldExtCount(v *DownlinkUEAssociatedLPPaTransport) *int64 {
	return &v.extCount
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldExtData(v *DownlinkUEAssociatedLPPaTransport) *[][]byte {
	return &v.extData
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldExtOrigin(v *DownlinkUEAssociatedLPPaTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldExtPresent(v *DownlinkUEAssociatedLPPaTransport) *[]bool {
	return &v.extPresent
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldExtWire(v *DownlinkUEAssociatedLPPaTransport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldPerExtPadding(v *DownlinkUEAssociatedLPPaTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldPerPadding(v *DownlinkUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldProtocolIEsIndef(v *DownlinkUEAssociatedLPPaTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldReceived(v *DownlinkUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedAbsolute(v *DownlinkUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedBytes(v *DownlinkUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldReceivedLocation(v *DownlinkUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldReplay(v *DownlinkUEAssociatedLPPaTransport) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldStream(v *DownlinkUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.stream
}
func BridgeDownlinkUEAssociatedLPPaTransportFieldWithoutReplay(v *DownlinkUEAssociatedLPPaTransport) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *DownlinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudgetValue(v *DownlinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERChanged(v *DownlinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERChangedValue(v *DownlinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERLegacy(v *DownlinkUEAssociatedLPPaTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERNewValue(v *DownlinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERPlanned(v *DownlinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERTo(v *DownlinkUEAssociatedLPPaTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *DownlinkUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodUnmarshalAPERLegacy(v *DownlinkUEAssociatedLPPaTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDownlinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *DownlinkUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldCapture(v *DownlinkUEAssociatedLPPaTransportValueCodec) *func(DownlinkUEAssociatedLPPaTransport, aper.DecodeState) (DownlinkUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldCompare(v *DownlinkUEAssociatedLPPaTransportValueCodec) *func(DownlinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldContext(v *DownlinkUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldDecode(v *DownlinkUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (DownlinkUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldEncode(v *DownlinkUEAssociatedLPPaTransportValueCodec) *func(DownlinkUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecFieldPath(v *DownlinkUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecMethodEncodeBudgetValue(v DownlinkUEAssociatedLPPaTransportValueCodec, a0 DownlinkUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkUEAssociatedLPPaTransportValueCodecMethodEncodeChanged(v DownlinkUEAssociatedLPPaTransportValueCodec, a0 DownlinkUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEHRPDCompositeAvailableCapacityAPERValueFieldContext(v *EHRPDCompositeAvailableCapacityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDCompositeAvailableCapacityAPERValueFieldReceived(v *EHRPDCompositeAvailableCapacityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEHRPDCompositeAvailableCapacityAPERValueFieldReplay(v *EHRPDCompositeAvailableCapacityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDCompositeAvailableCapacityAPERValueFieldWithoutReplay(v *EHRPDCompositeAvailableCapacityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDCompositeAvailableCapacityFieldExtCount(v *EHRPDCompositeAvailableCapacity) *int64 {
	return &v.extCount
}
func BridgeEHRPDCompositeAvailableCapacityFieldExtData(v *EHRPDCompositeAvailableCapacity) *[][]byte {
	return &v.extData
}
func BridgeEHRPDCompositeAvailableCapacityFieldExtOrigin(v *EHRPDCompositeAvailableCapacity) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEHRPDCompositeAvailableCapacityFieldExtPresent(v *EHRPDCompositeAvailableCapacity) *[]bool {
	return &v.extPresent
}
func BridgeEHRPDCompositeAvailableCapacityFieldExtWire(v *EHRPDCompositeAvailableCapacity) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEHRPDCompositeAvailableCapacityFieldPerExtPadding(v *EHRPDCompositeAvailableCapacity) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEHRPDCompositeAvailableCapacityFieldPerPadding(v *EHRPDCompositeAvailableCapacity) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEHRPDCompositeAvailableCapacityFieldReceived(v *EHRPDCompositeAvailableCapacity) *bool {
	return &v.received
}
func BridgeEHRPDCompositeAvailableCapacityFieldReceivedAbsolute(v *EHRPDCompositeAvailableCapacity) *bool {
	return &v.receivedAbsolute
}
func BridgeEHRPDCompositeAvailableCapacityFieldReceivedBytes(v *EHRPDCompositeAvailableCapacity) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEHRPDCompositeAvailableCapacityFieldReceivedLocation(v *EHRPDCompositeAvailableCapacity) *aper.Location {
	return &v.receivedLocation
}
func BridgeEHRPDCompositeAvailableCapacityFieldReplay(v *EHRPDCompositeAvailableCapacity) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDCompositeAvailableCapacityFieldStream(v *EHRPDCompositeAvailableCapacity) *aper.WireSpan {
	return &v.stream
}
func BridgeEHRPDCompositeAvailableCapacityFieldWithoutReplay(v *EHRPDCompositeAvailableCapacity) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERBudget(v *EHRPDCompositeAvailableCapacity, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERBudgetValue(v *EHRPDCompositeAvailableCapacity, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERChanged(v *EHRPDCompositeAvailableCapacity, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERChangedValue(v *EHRPDCompositeAvailableCapacity, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERLegacy(v *EHRPDCompositeAvailableCapacity) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERNewValue(v *EHRPDCompositeAvailableCapacity, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERPlanned(v *EHRPDCompositeAvailableCapacity, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEHRPDCompositeAvailableCapacityMethodMarshalAPERTo(v *EHRPDCompositeAvailableCapacity, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEHRPDCompositeAvailableCapacityMethodUnmarshalAPERFrom(v *EHRPDCompositeAvailableCapacity, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEHRPDCompositeAvailableCapacityMethodUnmarshalAPERLegacy(v *EHRPDCompositeAvailableCapacity, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEHRPDCompositeAvailableCapacityMethodUnmarshalAPERWithOptions(v *EHRPDCompositeAvailableCapacity, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldCapture(v *EHRPDCompositeAvailableCapacityValueCodec) *func(EHRPDCompositeAvailableCapacity, aper.DecodeState) (EHRPDCompositeAvailableCapacity, aper.Snapshot) {
	return &v.capture
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldCompare(v *EHRPDCompositeAvailableCapacityValueCodec) *func(EHRPDCompositeAvailableCapacity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldContext(v *EHRPDCompositeAvailableCapacityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldDecode(v *EHRPDCompositeAvailableCapacityValueCodec) *func([]byte, aper.DecodeState) (EHRPDCompositeAvailableCapacity, error) {
	return &v.decode
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldEncode(v *EHRPDCompositeAvailableCapacityValueCodec) *func(EHRPDCompositeAvailableCapacity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecFieldPath(v *EHRPDCompositeAvailableCapacityValueCodec) *aper.Path {
	return &v.path
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecMethodEncodeBudgetValue(v EHRPDCompositeAvailableCapacityValueCodec, a0 EHRPDCompositeAvailableCapacity, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEHRPDCompositeAvailableCapacityValueCodecMethodEncodeChanged(v EHRPDCompositeAvailableCapacityValueCodec, a0 EHRPDCompositeAvailableCapacity, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemAPERValueFieldContext(v *EHRPDMultiSectorLoadReportingResponseItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemAPERValueFieldReceived(v *EHRPDMultiSectorLoadReportingResponseItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemAPERValueFieldReplay(v *EHRPDMultiSectorLoadReportingResponseItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemAPERValueFieldWithoutReplay(v *EHRPDMultiSectorLoadReportingResponseItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldExtCount(v *EHRPDMultiSectorLoadReportingResponseItem) *int64 {
	return &v.extCount
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldExtData(v *EHRPDMultiSectorLoadReportingResponseItem) *[][]byte {
	return &v.extData
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldExtOrigin(v *EHRPDMultiSectorLoadReportingResponseItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldExtPresent(v *EHRPDMultiSectorLoadReportingResponseItem) *[]bool {
	return &v.extPresent
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldExtWire(v *EHRPDMultiSectorLoadReportingResponseItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldPerExtPadding(v *EHRPDMultiSectorLoadReportingResponseItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldPerPadding(v *EHRPDMultiSectorLoadReportingResponseItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldReceived(v *EHRPDMultiSectorLoadReportingResponseItem) *bool {
	return &v.received
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldReceivedAbsolute(v *EHRPDMultiSectorLoadReportingResponseItem) *bool {
	return &v.receivedAbsolute
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldReceivedBytes(v *EHRPDMultiSectorLoadReportingResponseItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldReceivedLocation(v *EHRPDMultiSectorLoadReportingResponseItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldReplay(v *EHRPDMultiSectorLoadReportingResponseItem) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldStream(v *EHRPDMultiSectorLoadReportingResponseItem) *aper.WireSpan {
	return &v.stream
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemFieldWithoutReplay(v *EHRPDMultiSectorLoadReportingResponseItem) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERBudget(v *EHRPDMultiSectorLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERBudgetValue(v *EHRPDMultiSectorLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERChanged(v *EHRPDMultiSectorLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERChangedValue(v *EHRPDMultiSectorLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERLegacy(v *EHRPDMultiSectorLoadReportingResponseItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERNewValue(v *EHRPDMultiSectorLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERPlanned(v *EHRPDMultiSectorLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERTo(v *EHRPDMultiSectorLoadReportingResponseItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodUnmarshalAPERFrom(v *EHRPDMultiSectorLoadReportingResponseItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodUnmarshalAPERLegacy(v *EHRPDMultiSectorLoadReportingResponseItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemMethodUnmarshalAPERWithOptions(v *EHRPDMultiSectorLoadReportingResponseItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldCapture(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *func(EHRPDMultiSectorLoadReportingResponseItem, aper.DecodeState) (EHRPDMultiSectorLoadReportingResponseItem, aper.Snapshot) {
	return &v.capture
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldCompare(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *func(EHRPDMultiSectorLoadReportingResponseItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldContext(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldDecode(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *func([]byte, aper.DecodeState) (EHRPDMultiSectorLoadReportingResponseItem, error) {
	return &v.decode
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldEncode(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *func(EHRPDMultiSectorLoadReportingResponseItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecFieldPath(v *EHRPDMultiSectorLoadReportingResponseItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecMethodEncodeBudgetValue(v EHRPDMultiSectorLoadReportingResponseItemValueCodec, a0 EHRPDMultiSectorLoadReportingResponseItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEHRPDMultiSectorLoadReportingResponseItemValueCodecMethodEncodeChanged(v EHRPDMultiSectorLoadReportingResponseItemValueCodec, a0 EHRPDMultiSectorLoadReportingResponseItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEHRPDSectorLoadReportingResponseAPERValueFieldContext(v *EHRPDSectorLoadReportingResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDSectorLoadReportingResponseAPERValueFieldReceived(v *EHRPDSectorLoadReportingResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEHRPDSectorLoadReportingResponseAPERValueFieldReplay(v *EHRPDSectorLoadReportingResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDSectorLoadReportingResponseAPERValueFieldWithoutReplay(v *EHRPDSectorLoadReportingResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDSectorLoadReportingResponseFieldExtCount(v *EHRPDSectorLoadReportingResponse) *int64 {
	return &v.extCount
}
func BridgeEHRPDSectorLoadReportingResponseFieldExtData(v *EHRPDSectorLoadReportingResponse) *[][]byte {
	return &v.extData
}
func BridgeEHRPDSectorLoadReportingResponseFieldExtOrigin(v *EHRPDSectorLoadReportingResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEHRPDSectorLoadReportingResponseFieldExtPresent(v *EHRPDSectorLoadReportingResponse) *[]bool {
	return &v.extPresent
}
func BridgeEHRPDSectorLoadReportingResponseFieldExtWire(v *EHRPDSectorLoadReportingResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEHRPDSectorLoadReportingResponseFieldPerExtPadding(v *EHRPDSectorLoadReportingResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEHRPDSectorLoadReportingResponseFieldPerPadding(v *EHRPDSectorLoadReportingResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEHRPDSectorLoadReportingResponseFieldReceived(v *EHRPDSectorLoadReportingResponse) *bool {
	return &v.received
}
func BridgeEHRPDSectorLoadReportingResponseFieldReceivedAbsolute(v *EHRPDSectorLoadReportingResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeEHRPDSectorLoadReportingResponseFieldReceivedBytes(v *EHRPDSectorLoadReportingResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEHRPDSectorLoadReportingResponseFieldReceivedLocation(v *EHRPDSectorLoadReportingResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeEHRPDSectorLoadReportingResponseFieldReplay(v *EHRPDSectorLoadReportingResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeEHRPDSectorLoadReportingResponseFieldStream(v *EHRPDSectorLoadReportingResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeEHRPDSectorLoadReportingResponseFieldWithoutReplay(v *EHRPDSectorLoadReportingResponse) *bool {
	return &v.withoutReplay
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERBudget(v *EHRPDSectorLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERBudgetValue(v *EHRPDSectorLoadReportingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERChanged(v *EHRPDSectorLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERChangedValue(v *EHRPDSectorLoadReportingResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERLegacy(v *EHRPDSectorLoadReportingResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERNewValue(v *EHRPDSectorLoadReportingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERPlanned(v *EHRPDSectorLoadReportingResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEHRPDSectorLoadReportingResponseMethodMarshalAPERTo(v *EHRPDSectorLoadReportingResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEHRPDSectorLoadReportingResponseMethodUnmarshalAPERFrom(v *EHRPDSectorLoadReportingResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEHRPDSectorLoadReportingResponseMethodUnmarshalAPERLegacy(v *EHRPDSectorLoadReportingResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEHRPDSectorLoadReportingResponseMethodUnmarshalAPERWithOptions(v *EHRPDSectorLoadReportingResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldCapture(v *EHRPDSectorLoadReportingResponseValueCodec) *func(EHRPDSectorLoadReportingResponse, aper.DecodeState) (EHRPDSectorLoadReportingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldCompare(v *EHRPDSectorLoadReportingResponseValueCodec) *func(EHRPDSectorLoadReportingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldContext(v *EHRPDSectorLoadReportingResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldDecode(v *EHRPDSectorLoadReportingResponseValueCodec) *func([]byte, aper.DecodeState) (EHRPDSectorLoadReportingResponse, error) {
	return &v.decode
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldEncode(v *EHRPDSectorLoadReportingResponseValueCodec) *func(EHRPDSectorLoadReportingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecFieldPath(v *EHRPDSectorLoadReportingResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecMethodEncodeBudgetValue(v EHRPDSectorLoadReportingResponseValueCodec, a0 EHRPDSectorLoadReportingResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEHRPDSectorLoadReportingResponseValueCodecMethodEncodeChanged(v EHRPDSectorLoadReportingResponseValueCodec, a0 EHRPDSectorLoadReportingResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBIDAPERValueFieldContext(v *ENBIDAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeENBIDAPERValueFieldReceived(v *ENBIDAPERValue) *aper.WireSpan         { return &v.received }
func BridgeENBIDAPERValueFieldReplay(v *ENBIDAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeENBIDAPERValueFieldWithoutReplay(v *ENBIDAPERValue) *bool             { return &v.withoutReplay }
func BridgeENBIDFieldPerOpenTypePadding(v *ENBID) *aper.CompletePadding          { return &v.perOpenTypePadding }
func BridgeENBIDFieldPerPadding(v *ENBID) *aper.CompletePadding                  { return &v.perPadding }
func BridgeENBIDFieldReceived(v *ENBID) *bool                                    { return &v.received }
func BridgeENBIDFieldReceivedAbsolute(v *ENBID) *bool                            { return &v.receivedAbsolute }
func BridgeENBIDFieldReceivedBytes(v *ENBID) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeENBIDFieldReceivedLocation(v *ENBID) *aper.Location                   { return &v.receivedLocation }
func BridgeENBIDFieldReplay(v *ENBID) *aper.Snapshot                             { return &v.replay }
func BridgeENBIDFieldStream(v *ENBID) *aper.WireSpan                             { return &v.stream }
func BridgeENBIDFieldWithoutReplay(v *ENBID) *bool                               { return &v.withoutReplay }
func BridgeENBIDMethodMarshalAPERBudget(v *ENBID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBIDMethodMarshalAPERBudgetValue(v *ENBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBIDMethodMarshalAPERChanged(v *ENBID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBIDMethodMarshalAPERChangedValue(v *ENBID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBIDMethodMarshalAPERLegacy(v *ENBID) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeENBIDMethodMarshalAPERNewValue(v *ENBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBIDMethodMarshalAPERPlanned(v *ENBID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBIDMethodMarshalAPERTo(v *ENBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBIDMethodUnmarshalAPERFrom(v *ENBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBIDMethodUnmarshalAPERLegacy(v *ENBID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBIDMethodUnmarshalAPERWithOptions(v *ENBID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBIDValueCodecFieldCapture(v *ENBIDValueCodec) *func(ENBID, aper.DecodeState) (ENBID, aper.Snapshot) {
	return &v.capture
}
func BridgeENBIDValueCodecFieldCompare(v *ENBIDValueCodec) *func(ENBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBIDValueCodecFieldContext(v *ENBIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeENBIDValueCodecFieldDecode(v *ENBIDValueCodec) *func([]byte, aper.DecodeState) (ENBID, error) {
	return &v.decode
}
func BridgeENBIDValueCodecFieldEncode(v *ENBIDValueCodec) *func(ENBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBIDValueCodecFieldPath(v *ENBIDValueCodec) *aper.Path { return &v.path }
func BridgeENBIDValueCodecMethodEncodeBudgetValue(v ENBIDValueCodec, a0 ENBID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBIDValueCodecMethodEncodeChanged(v ENBIDValueCodec, a0 ENBID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBX2ExtTLAAPERValueFieldContext(v *ENBX2ExtTLAAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAAPERValueFieldReceived(v *ENBX2ExtTLAAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBX2ExtTLAAPERValueFieldReplay(v *ENBX2ExtTLAAPERValue) *aper.Snapshot { return &v.replay }
func BridgeENBX2ExtTLAAPERValueFieldWithoutReplay(v *ENBX2ExtTLAAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBX2ExtTLAFieldExtCount(v *ENBX2ExtTLA) *int64                { return &v.extCount }
func BridgeENBX2ExtTLAFieldExtData(v *ENBX2ExtTLA) *[][]byte              { return &v.extData }
func BridgeENBX2ExtTLAFieldExtOrigin(v *ENBX2ExtTLA) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeENBX2ExtTLAFieldExtPresent(v *ENBX2ExtTLA) *[]bool             { return &v.extPresent }
func BridgeENBX2ExtTLAFieldExtWire(v *ENBX2ExtTLA) *[]aper.WireSpan       { return &v.extWire }
func BridgeENBX2ExtTLAFieldGTPTLAaIndef(v *ENBX2ExtTLA) *bool             { return &v.gTPTLAaIndef }
func BridgeENBX2ExtTLAFieldIEExtensionsIndef(v *ENBX2ExtTLA) *bool        { return &v.iEExtensionsIndef }
func BridgeENBX2ExtTLAFieldPerExtPadding(v *ENBX2ExtTLA) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBX2ExtTLAFieldPerPadding(v *ENBX2ExtTLA) *aper.FinalPadding { return &v.perPadding }
func BridgeENBX2ExtTLAFieldReceived(v *ENBX2ExtTLA) *bool                { return &v.received }
func BridgeENBX2ExtTLAFieldReceivedAbsolute(v *ENBX2ExtTLA) *bool        { return &v.receivedAbsolute }
func BridgeENBX2ExtTLAFieldReceivedBytes(v *ENBX2ExtTLA) *aper.WireSpan  { return &v.receivedBytes }
func BridgeENBX2ExtTLAFieldReceivedLocation(v *ENBX2ExtTLA) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBX2ExtTLAFieldReplay(v *ENBX2ExtTLA) *aper.Snapshot { return &v.replay }
func BridgeENBX2ExtTLAFieldStream(v *ENBX2ExtTLA) *aper.WireSpan { return &v.stream }
func BridgeENBX2ExtTLAFieldWithoutReplay(v *ENBX2ExtTLA) *bool   { return &v.withoutReplay }
func BridgeENBX2ExtTLAMethodMarshalAPERBudget(v *ENBX2ExtTLA, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBX2ExtTLAMethodMarshalAPERBudgetValue(v *ENBX2ExtTLA, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBX2ExtTLAMethodMarshalAPERChanged(v *ENBX2ExtTLA, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBX2ExtTLAMethodMarshalAPERChangedValue(v *ENBX2ExtTLA, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBX2ExtTLAMethodMarshalAPERLegacy(v *ENBX2ExtTLA) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBX2ExtTLAMethodMarshalAPERNewValue(v *ENBX2ExtTLA, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBX2ExtTLAMethodMarshalAPERPlanned(v *ENBX2ExtTLA, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBX2ExtTLAMethodMarshalAPERTo(v *ENBX2ExtTLA, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBX2ExtTLAMethodUnmarshalAPERFrom(v *ENBX2ExtTLA, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBX2ExtTLAMethodUnmarshalAPERLegacy(v *ENBX2ExtTLA, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBX2ExtTLAMethodUnmarshalAPERWithOptions(v *ENBX2ExtTLA, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBX2ExtTLAValueCodecFieldCapture(v *ENBX2ExtTLAValueCodec) *func(ENBX2ExtTLA, aper.DecodeState) (ENBX2ExtTLA, aper.Snapshot) {
	return &v.capture
}
func BridgeENBX2ExtTLAValueCodecFieldCompare(v *ENBX2ExtTLAValueCodec) *func(ENBX2ExtTLA, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBX2ExtTLAValueCodecFieldContext(v *ENBX2ExtTLAValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAValueCodecFieldDecode(v *ENBX2ExtTLAValueCodec) *func([]byte, aper.DecodeState) (ENBX2ExtTLA, error) {
	return &v.decode
}
func BridgeENBX2ExtTLAValueCodecFieldEncode(v *ENBX2ExtTLAValueCodec) *func(ENBX2ExtTLA, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBX2ExtTLAValueCodecFieldPath(v *ENBX2ExtTLAValueCodec) *aper.Path { return &v.path }
func BridgeENBX2ExtTLAValueCodecMethodEncodeBudgetValue(v ENBX2ExtTLAValueCodec, a0 ENBX2ExtTLA, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBX2ExtTLAValueCodecMethodEncodeChanged(v ENBX2ExtTLAValueCodec, a0 ENBX2ExtTLA, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBX2ExtTLAsAPERValueFieldContext(v *ENBX2ExtTLAsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAsAPERValueFieldReceived(v *ENBX2ExtTLAsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBX2ExtTLAsAPERValueFieldReplay(v *ENBX2ExtTLAsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBX2ExtTLAsAPERValueFieldWithoutReplay(v *ENBX2ExtTLAsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBX2ExtTLAsValueCodecFieldCapture(v *ENBX2ExtTLAsValueCodec) *func(ENBX2ExtTLAs, aper.DecodeState) (ENBX2ExtTLAs, aper.Snapshot) {
	return &v.capture
}
func BridgeENBX2ExtTLAsValueCodecFieldCompare(v *ENBX2ExtTLAsValueCodec) *func(ENBX2ExtTLAs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBX2ExtTLAsValueCodecFieldContext(v *ENBX2ExtTLAsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBX2ExtTLAsValueCodecFieldDecode(v *ENBX2ExtTLAsValueCodec) *func([]byte, aper.DecodeState) (ENBX2ExtTLAs, error) {
	return &v.decode
}
func BridgeENBX2ExtTLAsValueCodecFieldEncode(v *ENBX2ExtTLAsValueCodec) *func(ENBX2ExtTLAs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBX2ExtTLAsValueCodecFieldPath(v *ENBX2ExtTLAsValueCodec) *aper.Path { return &v.path }
func BridgeENBX2ExtTLAsValueCodecMethodEncodeBudgetValue(v ENBX2ExtTLAsValueCodec, a0 ENBX2ExtTLAs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBX2ExtTLAsValueCodecMethodEncodeChanged(v ENBX2ExtTLAsValueCodec, a0 ENBX2ExtTLAs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemAPERValueFieldContext(v *ERABAdmittedItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemAPERValueFieldReceived(v *ERABAdmittedItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemAPERValueFieldReplay(v *ERABAdmittedItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemAPERValueFieldWithoutReplay(v *ERABAdmittedItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemERABAdmittedItemIEBindingFieldCodec(v *ERABAdmittedItemERABAdmittedItemIEBinding) *ERABAdmittedItemValueCodec {
	return &v.codec
}
func BridgeERABAdmittedItemERABAdmittedItemIEBindingFieldGet(v *ERABAdmittedItemERABAdmittedItemIEBinding) *func(*ERABAdmittedItemIEValue) (*ERABAdmittedItem, bool) {
	return &v.get
}
func BridgeERABAdmittedItemERABAdmittedItemIEBindingFieldInfo(v *ERABAdmittedItemERABAdmittedItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABAdmittedItemERABAdmittedItemIEBindingFieldInject(v *ERABAdmittedItemERABAdmittedItemIEBinding) *func(ERABAdmittedItem) ERABAdmittedItemIEValue {
	return &v.inject
}
func BridgeERABAdmittedItemFieldExtCount(v *ERABAdmittedItem) *int64   { return &v.extCount }
func BridgeERABAdmittedItemFieldExtData(v *ERABAdmittedItem) *[][]byte { return &v.extData }
func BridgeERABAdmittedItemFieldExtOrigin(v *ERABAdmittedItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABAdmittedItemFieldExtPresent(v *ERABAdmittedItem) *[]bool       { return &v.extPresent }
func BridgeERABAdmittedItemFieldExtWire(v *ERABAdmittedItem) *[]aper.WireSpan { return &v.extWire }
func BridgeERABAdmittedItemFieldIEExtensionsIndef(v *ERABAdmittedItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABAdmittedItemFieldPerExtPadding(v *ERABAdmittedItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABAdmittedItemFieldPerPadding(v *ERABAdmittedItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABAdmittedItemFieldReceived(v *ERABAdmittedItem) *bool { return &v.received }
func BridgeERABAdmittedItemFieldReceivedAbsolute(v *ERABAdmittedItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABAdmittedItemFieldReceivedBytes(v *ERABAdmittedItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABAdmittedItemFieldReceivedLocation(v *ERABAdmittedItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABAdmittedItemFieldReplay(v *ERABAdmittedItem) *aper.Snapshot { return &v.replay }
func BridgeERABAdmittedItemFieldStream(v *ERABAdmittedItem) *aper.WireSpan { return &v.stream }
func BridgeERABAdmittedItemFieldWithoutReplay(v *ERABAdmittedItem) *bool   { return &v.withoutReplay }
func BridgeERABAdmittedItemIEContainerAPERValueFieldContext(v *ERABAdmittedItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEContainerAPERValueFieldReceived(v *ERABAdmittedItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEContainerAPERValueFieldReplay(v *ERABAdmittedItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEContainerAPERValueFieldWithoutReplay(v *ERABAdmittedItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldCapture(v *ERABAdmittedItemIEContainerValueCodec) *func(ERABAdmittedItemIEContainer, aper.DecodeState) (ERABAdmittedItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldCompare(v *ERABAdmittedItemIEContainerValueCodec) *func(ERABAdmittedItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldContext(v *ERABAdmittedItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(v *ERABAdmittedItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemIEContainer, error) {
	return &v.decode
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(v *ERABAdmittedItemIEContainerValueCodec) *func(ERABAdmittedItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemIEContainerValueCodecFieldPath(v *ERABAdmittedItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemIEContainerValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemIEContainerValueCodec, a0 ERABAdmittedItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemIEContainerValueCodecMethodEncodeChanged(v ERABAdmittedItemIEContainerValueCodec, a0 ERABAdmittedItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemIEFieldAPERValueFieldContext(v *ERABAdmittedItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEFieldAPERValueFieldReceived(v *ERABAdmittedItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEFieldAPERValueFieldReplay(v *ERABAdmittedItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEFieldAPERValueFieldWithoutReplay(v *ERABAdmittedItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEFieldFieldReceived(v *ERABAdmittedItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABAdmittedItemIEFieldFieldReplay(v *ERABAdmittedItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEFieldFieldStream(v *ERABAdmittedItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABAdmittedItemIEFieldFieldWithoutReplay(v *ERABAdmittedItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(v *ERABAdmittedItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(v *ERABAdmittedItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldCapture(v *ERABAdmittedItemIEFieldValueCodec) *func(ERABAdmittedItemIEField, aper.DecodeState) (ERABAdmittedItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldCompare(v *ERABAdmittedItemIEFieldValueCodec) *func(ERABAdmittedItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldContext(v *ERABAdmittedItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldDecode(v *ERABAdmittedItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemIEField, error) {
	return &v.decode
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldEncode(v *ERABAdmittedItemIEFieldValueCodec) *func(ERABAdmittedItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemIEFieldValueCodecFieldPath(v *ERABAdmittedItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemIEFieldValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemIEFieldValueCodec, a0 ERABAdmittedItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemIEFieldValueCodecMethodEncodeChanged(v ERABAdmittedItemIEFieldValueCodec, a0 ERABAdmittedItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemIETableMethodInfoERABAdmittedItem(v ERABAdmittedItemIETable) s00.FieldInfo {
	return v.infoERABAdmittedItem()
}
func BridgeERABAdmittedItemIEValueERABIEContainerListAPERValueFieldContext(v *ERABAdmittedItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueERABIEContainerListAPERValueFieldReceived(v *ERABAdmittedItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEValueERABIEContainerListAPERValueFieldReplay(v *ERABAdmittedItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABAdmittedItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *func(ERABAdmittedItemIEValueERABIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *func(ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *func(ERABAdmittedItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABAdmittedItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemIEValueERABIEContainerListValueCodec, a0 ERABAdmittedItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABAdmittedItemIEValueERABIEContainerListValueCodec, a0 ERABAdmittedItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemIEValueFieldId(v *ERABAdmittedItemIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeERABAdmittedItemIEValueFieldIsOpaque(v *ERABAdmittedItemIEValue) *bool       { return &v.isOpaque }
func BridgeERABAdmittedItemIEValueFieldOpaque(v *ERABAdmittedItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABAdmittedItemIEValueFieldReceived(v *ERABAdmittedItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEValueFieldReplay(v *ERABAdmittedItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEValueFieldRowERABAdmittedItem(v *ERABAdmittedItemIEValue) **ERABAdmittedItem {
	return &v.rowERABAdmittedItem
}
func BridgeERABAdmittedItemIEValueMethodCaptureSemantics(v ERABAdmittedItemIEValue, a0 aper.SemanticCapture) ERABAdmittedItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABAdmittedItemIEValueMethodCompareSemantics(v ERABAdmittedItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABAdmittedItemIEValueMethodDecode(v ERABAdmittedItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABAdmittedItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABAdmittedItemIEValueMethodEncode(v ERABAdmittedItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABAdmittedItemIEValueMethodEncodeFresh(v ERABAdmittedItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABAdmittedItemIEValueMethodMatchesID(v ERABAdmittedItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABAdmittedItemIEValueMethodReason(v ERABAdmittedItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABAdmittedItemIEValueMethodRule(v ERABAdmittedItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABAdmittedItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABAdmittedItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABAdmittedItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *func(ERABAdmittedItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABAdmittedItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemIEValueProtocolIEContainerListValueCodec, a0 ERABAdmittedItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABAdmittedItemIEValueProtocolIEContainerListValueCodec, a0 ERABAdmittedItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedItemMethodMarshalAPERBudget(v *ERABAdmittedItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABAdmittedItemMethodMarshalAPERBudgetValue(v *ERABAdmittedItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABAdmittedItemMethodMarshalAPERChanged(v *ERABAdmittedItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABAdmittedItemMethodMarshalAPERChangedValue(v *ERABAdmittedItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABAdmittedItemMethodMarshalAPERLegacy(v *ERABAdmittedItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABAdmittedItemMethodMarshalAPERNewValue(v *ERABAdmittedItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABAdmittedItemMethodMarshalAPERPlanned(v *ERABAdmittedItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABAdmittedItemMethodMarshalAPERTo(v *ERABAdmittedItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABAdmittedItemMethodUnmarshalAPERFrom(v *ERABAdmittedItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABAdmittedItemMethodUnmarshalAPERLegacy(v *ERABAdmittedItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABAdmittedItemMethodUnmarshalAPERWithOptions(v *ERABAdmittedItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABAdmittedItemValueCodecFieldCapture(v *ERABAdmittedItemValueCodec) *func(ERABAdmittedItem, aper.DecodeState) (ERABAdmittedItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedItemValueCodecFieldCompare(v *ERABAdmittedItemValueCodec) *func(ERABAdmittedItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedItemValueCodecFieldContext(v *ERABAdmittedItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedItemValueCodecFieldDecode(v *ERABAdmittedItemValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedItem, error) {
	return &v.decode
}
func BridgeERABAdmittedItemValueCodecFieldEncode(v *ERABAdmittedItemValueCodec) *func(ERABAdmittedItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedItemValueCodecFieldPath(v *ERABAdmittedItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedItemValueCodecMethodEncodeBudgetValue(v ERABAdmittedItemValueCodec, a0 ERABAdmittedItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedItemValueCodecMethodEncodeChanged(v ERABAdmittedItemValueCodec, a0 ERABAdmittedItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABAdmittedListAPERValueFieldContext(v *ERABAdmittedListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedListAPERValueFieldReceived(v *ERABAdmittedListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABAdmittedListAPERValueFieldReplay(v *ERABAdmittedListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABAdmittedListAPERValueFieldWithoutReplay(v *ERABAdmittedListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABAdmittedListValueCodecFieldCapture(v *ERABAdmittedListValueCodec) *func(ERABAdmittedList, aper.DecodeState) (ERABAdmittedList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABAdmittedListValueCodecFieldCompare(v *ERABAdmittedListValueCodec) *func(ERABAdmittedList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABAdmittedListValueCodecFieldContext(v *ERABAdmittedListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABAdmittedListValueCodecFieldDecode(v *ERABAdmittedListValueCodec) *func([]byte, aper.DecodeState) (ERABAdmittedList, error) {
	return &v.decode
}
func BridgeERABAdmittedListValueCodecFieldEncode(v *ERABAdmittedListValueCodec) *func(ERABAdmittedList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABAdmittedListValueCodecFieldPath(v *ERABAdmittedListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABAdmittedListValueCodecMethodEncodeBudgetValue(v ERABAdmittedListValueCodec, a0 ERABAdmittedList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABAdmittedListValueCodecMethodEncodeChanged(v ERABAdmittedListValueCodec, a0 ERABAdmittedList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemAPERValueFieldContext(v *ERABDataForwardingItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemAPERValueFieldReceived(v *ERABDataForwardingItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemAPERValueFieldReplay(v *ERABDataForwardingItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemAPERValueFieldWithoutReplay(v *ERABDataForwardingItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemERABDataForwardingItemIEBindingFieldCodec(v *ERABDataForwardingItemERABDataForwardingItemIEBinding) *ERABDataForwardingItemValueCodec {
	return &v.codec
}
func BridgeERABDataForwardingItemERABDataForwardingItemIEBindingFieldGet(v *ERABDataForwardingItemERABDataForwardingItemIEBinding) *func(*ERABDataForwardingItemIEValue) (*ERABDataForwardingItem, bool) {
	return &v.get
}
func BridgeERABDataForwardingItemERABDataForwardingItemIEBindingFieldInfo(v *ERABDataForwardingItemERABDataForwardingItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABDataForwardingItemERABDataForwardingItemIEBindingFieldInject(v *ERABDataForwardingItemERABDataForwardingItemIEBinding) *func(ERABDataForwardingItem) ERABDataForwardingItemIEValue {
	return &v.inject
}
func BridgeERABDataForwardingItemFieldExtCount(v *ERABDataForwardingItem) *int64   { return &v.extCount }
func BridgeERABDataForwardingItemFieldExtData(v *ERABDataForwardingItem) *[][]byte { return &v.extData }
func BridgeERABDataForwardingItemFieldExtOrigin(v *ERABDataForwardingItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABDataForwardingItemFieldExtPresent(v *ERABDataForwardingItem) *[]bool {
	return &v.extPresent
}
func BridgeERABDataForwardingItemFieldExtWire(v *ERABDataForwardingItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABDataForwardingItemFieldIEExtensionsIndef(v *ERABDataForwardingItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABDataForwardingItemFieldPerExtPadding(v *ERABDataForwardingItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABDataForwardingItemFieldPerPadding(v *ERABDataForwardingItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABDataForwardingItemFieldReceived(v *ERABDataForwardingItem) *bool { return &v.received }
func BridgeERABDataForwardingItemFieldReceivedAbsolute(v *ERABDataForwardingItem) *bool {
	return &v.receivedAbsolute
}
func BridgeERABDataForwardingItemFieldReceivedBytes(v *ERABDataForwardingItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABDataForwardingItemFieldReceivedLocation(v *ERABDataForwardingItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABDataForwardingItemFieldReplay(v *ERABDataForwardingItem) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemFieldStream(v *ERABDataForwardingItem) *aper.WireSpan {
	return &v.stream
}
func BridgeERABDataForwardingItemFieldWithoutReplay(v *ERABDataForwardingItem) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEContainerAPERValueFieldContext(v *ERABDataForwardingItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEContainerAPERValueFieldReceived(v *ERABDataForwardingItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEContainerAPERValueFieldReplay(v *ERABDataForwardingItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEContainerAPERValueFieldWithoutReplay(v *ERABDataForwardingItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldCapture(v *ERABDataForwardingItemIEContainerValueCodec) *func(ERABDataForwardingItemIEContainer, aper.DecodeState) (ERABDataForwardingItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldCompare(v *ERABDataForwardingItemIEContainerValueCodec) *func(ERABDataForwardingItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldContext(v *ERABDataForwardingItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldDecode(v *ERABDataForwardingItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemIEContainer, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldEncode(v *ERABDataForwardingItemIEContainerValueCodec) *func(ERABDataForwardingItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemIEContainerValueCodecFieldPath(v *ERABDataForwardingItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemIEContainerValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemIEContainerValueCodec, a0 ERABDataForwardingItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemIEContainerValueCodecMethodEncodeChanged(v ERABDataForwardingItemIEContainerValueCodec, a0 ERABDataForwardingItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemIEFieldAPERValueFieldContext(v *ERABDataForwardingItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEFieldAPERValueFieldReceived(v *ERABDataForwardingItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEFieldAPERValueFieldReplay(v *ERABDataForwardingItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEFieldAPERValueFieldWithoutReplay(v *ERABDataForwardingItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEFieldFieldReceived(v *ERABDataForwardingItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABDataForwardingItemIEFieldFieldReplay(v *ERABDataForwardingItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEFieldFieldStream(v *ERABDataForwardingItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABDataForwardingItemIEFieldFieldWithoutReplay(v *ERABDataForwardingItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEFieldMethodMarshalAPERTo(v *ERABDataForwardingItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABDataForwardingItemIEFieldMethodUnmarshalAPERFrom(v *ERABDataForwardingItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldCapture(v *ERABDataForwardingItemIEFieldValueCodec) *func(ERABDataForwardingItemIEField, aper.DecodeState) (ERABDataForwardingItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldCompare(v *ERABDataForwardingItemIEFieldValueCodec) *func(ERABDataForwardingItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldContext(v *ERABDataForwardingItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldDecode(v *ERABDataForwardingItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemIEField, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldEncode(v *ERABDataForwardingItemIEFieldValueCodec) *func(ERABDataForwardingItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemIEFieldValueCodecFieldPath(v *ERABDataForwardingItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemIEFieldValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemIEFieldValueCodec, a0 ERABDataForwardingItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemIEFieldValueCodecMethodEncodeChanged(v ERABDataForwardingItemIEFieldValueCodec, a0 ERABDataForwardingItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemIETableMethodInfoERABDataForwardingItem(v ERABDataForwardingItemIETable) s00.FieldInfo {
	return v.infoERABDataForwardingItem()
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListAPERValueFieldContext(v *ERABDataForwardingItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListAPERValueFieldReceived(v *ERABDataForwardingItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListAPERValueFieldReplay(v *ERABDataForwardingItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABDataForwardingItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueERABIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABDataForwardingItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemIEValueERABIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABDataForwardingItemIEValueERABIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemIEValueFieldId(v *ERABDataForwardingItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABDataForwardingItemIEValueFieldIsOpaque(v *ERABDataForwardingItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABDataForwardingItemIEValueFieldOpaque(v *ERABDataForwardingItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABDataForwardingItemIEValueFieldReceived(v *ERABDataForwardingItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEValueFieldReplay(v *ERABDataForwardingItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEValueFieldRowERABDataForwardingItem(v *ERABDataForwardingItemIEValue) **ERABDataForwardingItem {
	return &v.rowERABDataForwardingItem
}
func BridgeERABDataForwardingItemIEValueMethodCaptureSemantics(v ERABDataForwardingItemIEValue, a0 aper.SemanticCapture) ERABDataForwardingItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABDataForwardingItemIEValueMethodCompareSemantics(v ERABDataForwardingItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABDataForwardingItemIEValueMethodDecode(v ERABDataForwardingItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABDataForwardingItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABDataForwardingItemIEValueMethodEncode(v ERABDataForwardingItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABDataForwardingItemIEValueMethodEncodeFresh(v ERABDataForwardingItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABDataForwardingItemIEValueMethodMatchesID(v ERABDataForwardingItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABDataForwardingItemIEValueMethodReason(v ERABDataForwardingItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABDataForwardingItemIEValueMethodRule(v ERABDataForwardingItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABDataForwardingItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABDataForwardingItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *func(ERABDataForwardingItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABDataForwardingItemIEValueProtocolIEContainerListValueCodec, a0 ERABDataForwardingItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABDataForwardingItemMethodMarshalAPERBudget(v *ERABDataForwardingItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABDataForwardingItemMethodMarshalAPERBudgetValue(v *ERABDataForwardingItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABDataForwardingItemMethodMarshalAPERChanged(v *ERABDataForwardingItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABDataForwardingItemMethodMarshalAPERChangedValue(v *ERABDataForwardingItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemMethodMarshalAPERLegacy(v *ERABDataForwardingItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABDataForwardingItemMethodMarshalAPERNewValue(v *ERABDataForwardingItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABDataForwardingItemMethodMarshalAPERPlanned(v *ERABDataForwardingItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABDataForwardingItemMethodMarshalAPERTo(v *ERABDataForwardingItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABDataForwardingItemMethodUnmarshalAPERFrom(v *ERABDataForwardingItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABDataForwardingItemMethodUnmarshalAPERLegacy(v *ERABDataForwardingItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABDataForwardingItemMethodUnmarshalAPERWithOptions(v *ERABDataForwardingItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABDataForwardingItemValueCodecFieldCapture(v *ERABDataForwardingItemValueCodec) *func(ERABDataForwardingItem, aper.DecodeState) (ERABDataForwardingItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABDataForwardingItemValueCodecFieldCompare(v *ERABDataForwardingItemValueCodec) *func(ERABDataForwardingItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABDataForwardingItemValueCodecFieldContext(v *ERABDataForwardingItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABDataForwardingItemValueCodecFieldDecode(v *ERABDataForwardingItemValueCodec) *func([]byte, aper.DecodeState) (ERABDataForwardingItem, error) {
	return &v.decode
}
func BridgeERABDataForwardingItemValueCodecFieldEncode(v *ERABDataForwardingItemValueCodec) *func(ERABDataForwardingItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABDataForwardingItemValueCodecFieldPath(v *ERABDataForwardingItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABDataForwardingItemValueCodecMethodEncodeBudgetValue(v ERABDataForwardingItemValueCodec, a0 ERABDataForwardingItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABDataForwardingItemValueCodecMethodEncodeChanged(v ERABDataForwardingItemValueCodec, a0 ERABDataForwardingItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBindingFieldCodec(v *ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) *ERABFailedToResumeItemResumeReqValueCodec {
	return &v.codec
}
func BridgeERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBindingFieldGet(v *ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) *func(*ERABFailedToResumeItemResumeReqIEValue) (*ERABFailedToResumeItemResumeReq, bool) {
	return &v.get
}
func BridgeERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBindingFieldInfo(v *ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBindingFieldInject(v *ERABFailedToResumeItemResumeReqERABFailedToResumeItemResumeReqIEBinding) *func(ERABFailedToResumeItemResumeReq) ERABFailedToResumeItemResumeReqIEValue {
	return &v.inject
}
func BridgeERABFailedToResumeItemResumeReqFieldExtCount(v *ERABFailedToResumeItemResumeReq) *int64 {
	return &v.extCount
}
func BridgeERABFailedToResumeItemResumeReqFieldExtData(v *ERABFailedToResumeItemResumeReq) *[][]byte {
	return &v.extData
}
func BridgeERABFailedToResumeItemResumeReqFieldExtOrigin(v *ERABFailedToResumeItemResumeReq) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABFailedToResumeItemResumeReqFieldExtPresent(v *ERABFailedToResumeItemResumeReq) *[]bool {
	return &v.extPresent
}
func BridgeERABFailedToResumeItemResumeReqFieldExtWire(v *ERABFailedToResumeItemResumeReq) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABFailedToResumeItemResumeReqFieldIEExtensionsIndef(v *ERABFailedToResumeItemResumeReq) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABFailedToResumeItemResumeReqFieldPerExtPadding(v *ERABFailedToResumeItemResumeReq) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABFailedToResumeItemResumeReqFieldPerPadding(v *ERABFailedToResumeItemResumeReq) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABFailedToResumeItemResumeReqFieldReceived(v *ERABFailedToResumeItemResumeReq) *bool {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqFieldReceivedAbsolute(v *ERABFailedToResumeItemResumeReq) *bool {
	return &v.receivedAbsolute
}
func BridgeERABFailedToResumeItemResumeReqFieldReceivedBytes(v *ERABFailedToResumeItemResumeReq) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABFailedToResumeItemResumeReqFieldReceivedLocation(v *ERABFailedToResumeItemResumeReq) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABFailedToResumeItemResumeReqFieldReplay(v *ERABFailedToResumeItemResumeReq) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqFieldStream(v *ERABFailedToResumeItemResumeReq) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedToResumeItemResumeReqFieldWithoutReplay(v *ERABFailedToResumeItemResumeReq) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEContainerAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEContainerAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEContainerAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEContainerAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *func(ERABFailedToResumeItemResumeReqIEContainer, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *func(ERABFailedToResumeItemResumeReqIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEContainer, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *func(ERABFailedToResumeItemResumeReqIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqIEContainerValueCodec, a0 ERABFailedToResumeItemResumeReqIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqIEContainerValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqIEContainerValueCodec, a0 ERABFailedToResumeItemResumeReqIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqIEFieldAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEFieldAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEFieldAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEFieldAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEFieldFieldReceived(v *ERABFailedToResumeItemResumeReqIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEFieldFieldReplay(v *ERABFailedToResumeItemResumeReqIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEFieldFieldStream(v *ERABFailedToResumeItemResumeReqIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedToResumeItemResumeReqIEFieldFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEFieldMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeReqIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeReqIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *func(ERABFailedToResumeItemResumeReqIEField, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *func(ERABFailedToResumeItemResumeReqIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEField, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *func(ERABFailedToResumeItemResumeReqIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqIEFieldValueCodec, a0 ERABFailedToResumeItemResumeReqIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqIEFieldValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqIEFieldValueCodec, a0 ERABFailedToResumeItemResumeReqIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqIETableMethodInfoERABFailedToResumeItemResumeReq(v ERABFailedToResumeItemResumeReqIETable) s00.FieldInfo {
	return v.infoERABFailedToResumeItemResumeReq()
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqIEValueERABIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldId(v *ERABFailedToResumeItemResumeReqIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldIsOpaque(v *ERABFailedToResumeItemResumeReqIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldOpaque(v *ERABFailedToResumeItemResumeReqIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEValueFieldRowERABFailedToResumeItemResumeReq(v *ERABFailedToResumeItemResumeReqIEValue) **ERABFailedToResumeItemResumeReq {
	return &v.rowERABFailedToResumeItemResumeReq
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodCaptureSemantics(v ERABFailedToResumeItemResumeReqIEValue, a0 aper.SemanticCapture) ERABFailedToResumeItemResumeReqIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodCompareSemantics(v ERABFailedToResumeItemResumeReqIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodDecode(v ERABFailedToResumeItemResumeReqIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABFailedToResumeItemResumeReqIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodEncode(v ERABFailedToResumeItemResumeReqIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodEncodeFresh(v ERABFailedToResumeItemResumeReqIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodMatchesID(v ERABFailedToResumeItemResumeReqIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodReason(v ERABFailedToResumeItemResumeReqIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABFailedToResumeItemResumeReqIEValueMethodRule(v ERABFailedToResumeItemResumeReqIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *func(ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerListValueCodec, a0 ERABFailedToResumeItemResumeReqIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERBudget(v *ERABFailedToResumeItemResumeReq, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERBudgetValue(v *ERABFailedToResumeItemResumeReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERChanged(v *ERABFailedToResumeItemResumeReq, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERChangedValue(v *ERABFailedToResumeItemResumeReq, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERLegacy(v *ERABFailedToResumeItemResumeReq) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERNewValue(v *ERABFailedToResumeItemResumeReq, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERPlanned(v *ERABFailedToResumeItemResumeReq, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeReq, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeReqMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeReq, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeReqMethodUnmarshalAPERLegacy(v *ERABFailedToResumeItemResumeReq, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABFailedToResumeItemResumeReqMethodUnmarshalAPERWithOptions(v *ERABFailedToResumeItemResumeReq, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldCapture(v *ERABFailedToResumeItemResumeReqValueCodec) *func(ERABFailedToResumeItemResumeReq, aper.DecodeState) (ERABFailedToResumeItemResumeReq, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldCompare(v *ERABFailedToResumeItemResumeReqValueCodec) *func(ERABFailedToResumeItemResumeReq, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldContext(v *ERABFailedToResumeItemResumeReqValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldDecode(v *ERABFailedToResumeItemResumeReqValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToResumeItemResumeReq, error) {
	return &v.decode
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldEncode(v *ERABFailedToResumeItemResumeReqValueCodec) *func(ERABFailedToResumeItemResumeReq, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeItemResumeReqValueCodecFieldPath(v *ERABFailedToResumeItemResumeReqValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeItemResumeReqValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeItemResumeReqValueCodec, a0 ERABFailedToResumeItemResumeReq, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeReqValueCodecMethodEncodeChanged(v ERABFailedToResumeItemResumeReqValueCodec, a0 ERABFailedToResumeItemResumeReq, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToResumeItemResumeResAPERValueFieldContext(v *ERABFailedToResumeItemResumeResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeResAPERValueFieldReceived(v *ERABFailedToResumeItemResumeResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeResAPERValueFieldReplay(v *ERABFailedToResumeItemResumeResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeResFieldExtCount(v *ERABFailedToResumeItemResumeRes) *int64 {
	return &v.extCount
}
func BridgeERABFailedToResumeItemResumeResFieldExtData(v *ERABFailedToResumeItemResumeRes) *[][]byte {
	return &v.extData
}
func BridgeERABFailedToResumeItemResumeResFieldExtOrigin(v *ERABFailedToResumeItemResumeRes) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABFailedToResumeItemResumeResFieldExtPresent(v *ERABFailedToResumeItemResumeRes) *[]bool {
	return &v.extPresent
}
func BridgeERABFailedToResumeItemResumeResFieldExtWire(v *ERABFailedToResumeItemResumeRes) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABFailedToResumeItemResumeResFieldIEExtensionsIndef(v *ERABFailedToResumeItemResumeRes) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABFailedToResumeItemResumeResFieldPerExtPadding(v *ERABFailedToResumeItemResumeRes) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABFailedToResumeItemResumeResFieldPerPadding(v *ERABFailedToResumeItemResumeRes) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABFailedToResumeItemResumeResFieldReceived(v *ERABFailedToResumeItemResumeRes) *bool {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeResFieldReceivedAbsolute(v *ERABFailedToResumeItemResumeRes) *bool {
	return &v.receivedAbsolute
}
func BridgeERABFailedToResumeItemResumeResFieldReceivedBytes(v *ERABFailedToResumeItemResumeRes) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABFailedToResumeItemResumeResFieldReceivedLocation(v *ERABFailedToResumeItemResumeRes) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABFailedToResumeItemResumeResFieldReplay(v *ERABFailedToResumeItemResumeRes) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResFieldStream(v *ERABFailedToResumeItemResumeRes) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedToResumeItemResumeResFieldWithoutReplay(v *ERABFailedToResumeItemResumeRes) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeResIEContainerAPERValueFieldContext(v *ERABFailedToResumeItemResumeResIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeItemResumeResIEContainerAPERValueFieldReceived(v *ERABFailedToResumeItemResumeResIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeResIEContainerAPERValueFieldReplay(v *ERABFailedToResumeItemResumeResIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResIEContainerAPERValueFieldWithoutReplay(v *ERABFailedToResumeItemResumeResIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeResIEFieldFieldReceived(v *ERABFailedToResumeItemResumeResIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeResIEFieldFieldReplay(v *ERABFailedToResumeItemResumeResIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResIEFieldFieldStream(v *ERABFailedToResumeItemResumeResIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedToResumeItemResumeResIEFieldFieldWithoutReplay(v *ERABFailedToResumeItemResumeResIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToResumeItemResumeResIEFieldMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeResIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeResIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldId(v *ERABFailedToResumeItemResumeResIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldIsOpaque(v *ERABFailedToResumeItemResumeResIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldOpaque(v *ERABFailedToResumeItemResumeResIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldReceived(v *ERABFailedToResumeItemResumeResIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldReplay(v *ERABFailedToResumeItemResumeResIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToResumeItemResumeResIEValueFieldRowERABFailedToResumeItemResumeRes(v *ERABFailedToResumeItemResumeResIEValue) **ERABFailedToResumeItemResumeRes {
	return &v.rowERABFailedToResumeItemResumeRes
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodCaptureSemantics(v ERABFailedToResumeItemResumeResIEValue, a0 aper.SemanticCapture) ERABFailedToResumeItemResumeResIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodCompareSemantics(v ERABFailedToResumeItemResumeResIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodDecode(v ERABFailedToResumeItemResumeResIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABFailedToResumeItemResumeResIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodEncode(v ERABFailedToResumeItemResumeResIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodEncodeFresh(v ERABFailedToResumeItemResumeResIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodMatchesID(v ERABFailedToResumeItemResumeResIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodReason(v ERABFailedToResumeItemResumeResIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABFailedToResumeItemResumeResIEValueMethodRule(v ERABFailedToResumeItemResumeResIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERBudget(v *ERABFailedToResumeItemResumeRes, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERBudgetValue(v *ERABFailedToResumeItemResumeRes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERChanged(v *ERABFailedToResumeItemResumeRes, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERChangedValue(v *ERABFailedToResumeItemResumeRes, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERLegacy(v *ERABFailedToResumeItemResumeRes) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERNewValue(v *ERABFailedToResumeItemResumeRes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERPlanned(v *ERABFailedToResumeItemResumeRes, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABFailedToResumeItemResumeResMethodMarshalAPERTo(v *ERABFailedToResumeItemResumeRes, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToResumeItemResumeResMethodUnmarshalAPERFrom(v *ERABFailedToResumeItemResumeRes, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToResumeItemResumeResMethodUnmarshalAPERLegacy(v *ERABFailedToResumeItemResumeRes, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABFailedToResumeItemResumeResMethodUnmarshalAPERWithOptions(v *ERABFailedToResumeItemResumeRes, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func (v *ERABAdmittedItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 20:
		if value, ok := v.AsERABAdmittedItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABDataForwardingItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 14:
		if value, ok := v.AsERABDataForwardingItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABFailedToResumeItemResumeReqIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 236:
		if value, ok := v.AsERABFailedToResumeItemResumeReq(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ERABFailedToResumeItemResumeResIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 238:
		if value, ok := v.AsERABFailedToResumeItemResumeRes(); ok {
			return value, true
		}
	}
	return nil, false
}
