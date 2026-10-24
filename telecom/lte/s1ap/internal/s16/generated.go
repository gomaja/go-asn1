// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s16 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s16

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ERABItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABItemIEValue].
type ERABItemIEValueProtocolIESingleContainer = ERABItemIEField

// ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer = ERABFailedtoSetupItemHOReqAckIEField

// ERABSetupItemBearerSUResIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueProtocolIESingleContainer = ERABSetupItemBearerSUResIEField

// ERABModifyItemBearerModResIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueProtocolIESingleContainer = ERABModifyItemBearerModResIEField

// ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer = ERABReleaseItemBearerRelCompIEField

// ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer = ERABSetupItemCtxtSUResIEField

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer = ERABNotToBeModifiedItemBearerModIndIEField

// ERABModifyItemBearerModConfIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueProtocolIESingleContainer = ERABModifyItemBearerModConfIEField

// ERABItemERABItemIEBinding is the concrete IEBinding[ERABItem, ERABItemIEValue].
type ERABItemERABItemIEBinding struct {
	info   s00.FieldInfo
	codec  ERABItemValueCodec
	inject func(ERABItem,

	) ERABItemIEValue

	get func(*ERABItemIEValue,

	) (*ERABItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABItemERABItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABItemERABItemIEBinding) Codec() ERABItemValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ERABItemERABItemIEBinding) New(value ERABItem,

) (ERABItemIEField, error) {
	if b.inject == nil {
		return ERABItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABItemERABItemIEBinding) Get(field *ERABItemIEField) (*ERABItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABItemValueCodec is the concrete ValueCodec[ERABItem].
type ERABItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItem,

		error)
	encode func(ERABItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItem, aper.DecodeState,

	) (ERABItem, aper.Snapshot,

	)
	compare func(ERABItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemValueCodec) New(value ERABItem,

) (ERABItemAPERValue, error) {
	if c.encode == nil {
		return ERABItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemValueCodec) EncodeAPER(value ERABItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemValueCodec) encodeBudgetValue(value ERABItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemValueCodec) encodeChanged(value ERABItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEField is the concrete ProtocolIEField[ERABItemIEValue].
type ERABItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEField) WithoutReplay() ERABItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABItemIEField{}
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
	var zero ERABItemIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
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

// ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding is the concrete IEBinding[ERABFailedToSetupItemHOReqAck, ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding struct {
	info   s00.FieldInfo
	codec  ERABFailedToSetupItemHOReqAckValueCodec
	inject func(ERABFailedToSetupItemHOReqAck,

	) ERABFailedtoSetupItemHOReqAckIEValue

	get func(*ERABFailedtoSetupItemHOReqAckIEValue,

	) (*ERABFailedToSetupItemHOReqAck,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) Codec() ERABFailedToSetupItemHOReqAckValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) New(value ERABFailedToSetupItemHOReqAck,

) (ERABFailedtoSetupItemHOReqAckIEField, error) {
	if b.inject == nil {
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) Get(field *ERABFailedtoSetupItemHOReqAckIEField) (*ERABFailedToSetupItemHOReqAck,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABFailedToSetupItemHOReqAckValueCodec is the concrete ValueCodec[ERABFailedToSetupItemHOReqAck].
type ERABFailedToSetupItemHOReqAckValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAck,

		error)
	encode func(ERABFailedToSetupItemHOReqAck,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedToSetupItemHOReqAck, aper.DecodeState,

	) (ERABFailedToSetupItemHOReqAck, aper.Snapshot,

	)
	compare func(ERABFailedToSetupItemHOReqAck, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToSetupItemHOReqAckValueCodec) New(value ERABFailedToSetupItemHOReqAck,

) (ERABFailedToSetupItemHOReqAckAPERValue, error) {
	if c.encode == nil {
		return ERABFailedToSetupItemHOReqAckAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedToSetupItemHOReqAckAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedToSetupItemHOReqAckAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedToSetupItemHOReqAckAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToSetupItemHOReqAckValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedToSetupItemHOReqAckAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedToSetupItemHOReqAckAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedToSetupItemHOReqAckAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedToSetupItemHOReqAckAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedToSetupItemHOReqAckAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToSetupItemHOReqAckValueCodec) EncodeAPER(value ERABFailedToSetupItemHOReqAckAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedToSetupItemHOReqAckValueCodec) encodeBudgetValue(value ERABFailedToSetupItemHOReqAck,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToSetupItemHOReqAckValueCodec) encodeChanged(value ERABFailedToSetupItemHOReqAck,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEField is the concrete ProtocolIEField[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABFailedtoSetupItemHOReqAckIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEField) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABFailedtoSetupItemHOReqAckIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABFailedtoSetupItemHOReqAckIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABFailedtoSetupItemHOReqAckIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedtoSetupItemHOReqAckIEField{}
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
	var zero ERABFailedtoSetupItemHOReqAckIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyListBearerModConfValueCodec is the concrete ValueCodec[ERABModifyListBearerModConf].
type ERABModifyListBearerModConfValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyListBearerModConf,

		error)
	encode func(ERABModifyListBearerModConf,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyListBearerModConf, aper.DecodeState,

	) (ERABModifyListBearerModConf, aper.Snapshot,

	)
	compare func(ERABModifyListBearerModConf, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyListBearerModConfValueCodec) New(value ERABModifyListBearerModConf,

) (ERABModifyListBearerModConfAPERValue, error) {
	if c.encode == nil {
		return ERABModifyListBearerModConfAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyListBearerModConfAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyListBearerModConfAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyListBearerModConfAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyListBearerModConfValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyListBearerModConfAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyListBearerModConfAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyListBearerModConfAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyListBearerModConfAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyListBearerModConfAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyListBearerModConfValueCodec) EncodeAPER(value ERABModifyListBearerModConfAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyListBearerModConfValueCodec) encodeBudgetValue(value ERABModifyListBearerModConf,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyListBearerModConfValueCodec) encodeChanged(value ERABModifyListBearerModConf,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABListValueCodec is the concrete ValueCodec[ERABList].
type ERABListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABList,

		error)
	encode func(ERABList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABList, aper.DecodeState,

	) (ERABList, aper.Snapshot,

	)
	compare func(ERABList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABListValueCodec) New(value ERABList,

) (ERABListAPERValue, error) {
	if c.encode == nil {
		return ERABListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABListValueCodec) EncodeAPER(value ERABListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABListValueCodec) encodeBudgetValue(value ERABList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABListValueCodec) encodeChanged(value ERABList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedListBearerModIndValueCodec is the concrete ValueCodec[ERABNotToBeModifiedListBearerModInd].
type ERABNotToBeModifiedListBearerModIndValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedListBearerModInd,

		error)
	encode func(ERABNotToBeModifiedListBearerModInd,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedListBearerModInd, aper.DecodeState,

	) (ERABNotToBeModifiedListBearerModInd, aper.Snapshot,

	)
	compare func(ERABNotToBeModifiedListBearerModInd, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedListBearerModIndValueCodec) New(value ERABNotToBeModifiedListBearerModInd,

) (ERABNotToBeModifiedListBearerModIndAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedListBearerModIndAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedListBearerModIndAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedListBearerModIndValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedListBearerModIndAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedListBearerModIndAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedListBearerModIndAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedListBearerModIndAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedListBearerModIndAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedListBearerModIndValueCodec) EncodeAPER(value ERABNotToBeModifiedListBearerModIndAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedListBearerModIndValueCodec) encodeBudgetValue(value ERABNotToBeModifiedListBearerModInd,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedListBearerModIndValueCodec) encodeChanged(value ERABNotToBeModifiedListBearerModInd,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding is the concrete IEBinding[ERABModifyItemBearerModConf, ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding struct {
	info   s00.FieldInfo
	codec  ERABModifyItemBearerModConfValueCodec
	inject func(ERABModifyItemBearerModConf,

	) ERABModifyItemBearerModConfIEValue

	get func(*ERABModifyItemBearerModConfIEValue,

	) (*ERABModifyItemBearerModConf,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) Codec() ERABModifyItemBearerModConfValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) New(value ERABModifyItemBearerModConf,

) (ERABModifyItemBearerModConfIEField, error) {
	if b.inject == nil {
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyItemBearerModConfIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) Get(field *ERABModifyItemBearerModConfIEField) (*ERABModifyItemBearerModConf,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyItemBearerModConfValueCodec is the concrete ValueCodec[ERABModifyItemBearerModConf].
type ERABModifyItemBearerModConfValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConf,

		error)
	encode func(ERABModifyItemBearerModConf,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConf, aper.DecodeState,

	) (ERABModifyItemBearerModConf, aper.Snapshot,

	)
	compare func(ERABModifyItemBearerModConf, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfValueCodec) New(value ERABModifyItemBearerModConf,

) (ERABModifyItemBearerModConfAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfValueCodec) EncodeAPER(value ERABModifyItemBearerModConfAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConf,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfValueCodec) encodeChanged(value ERABModifyItemBearerModConf,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEField is the concrete ProtocolIEField[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModifyItemBearerModConfIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEField) WithoutReplay() ERABModifyItemBearerModConfIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModConfIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModConfIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABModifyItemBearerModConfIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModConfIEField{}
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
	var zero ERABModifyItemBearerModConfIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding is the concrete IEBinding[ERABModifyItemBearerModRes, ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding struct {
	info   s00.FieldInfo
	codec  ERABModifyItemBearerModResValueCodec
	inject func(ERABModifyItemBearerModRes,

	) ERABModifyItemBearerModResIEValue

	get func(*ERABModifyItemBearerModResIEValue,

	) (*ERABModifyItemBearerModRes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) Codec() ERABModifyItemBearerModResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) New(value ERABModifyItemBearerModRes,

) (ERABModifyItemBearerModResIEField, error) {
	if b.inject == nil {
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModifyItemBearerModResIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) Get(field *ERABModifyItemBearerModResIEField) (*ERABModifyItemBearerModRes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModifyItemBearerModResValueCodec is the concrete ValueCodec[ERABModifyItemBearerModRes].
type ERABModifyItemBearerModResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModRes,

		error)
	encode func(ERABModifyItemBearerModRes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModRes, aper.DecodeState,

	) (ERABModifyItemBearerModRes, aper.Snapshot,

	)
	compare func(ERABModifyItemBearerModRes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResValueCodec) New(value ERABModifyItemBearerModRes,

) (ERABModifyItemBearerModResAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResValueCodec) EncodeAPER(value ERABModifyItemBearerModResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResValueCodec) encodeBudgetValue(value ERABModifyItemBearerModRes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResValueCodec) encodeChanged(value ERABModifyItemBearerModRes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEField is the concrete ProtocolIEField[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModifyItemBearerModResIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEField) WithoutReplay() ERABModifyItemBearerModResIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModifyItemBearerModResIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModifyItemBearerModResIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABModifyItemBearerModResIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModResIEField{}
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
	var zero ERABModifyItemBearerModResIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABModifyListBearerModResValueCodec is the concrete ValueCodec[ERABModifyListBearerModRes].
type ERABModifyListBearerModResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyListBearerModRes,

		error)
	encode func(ERABModifyListBearerModRes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyListBearerModRes, aper.DecodeState,

	) (ERABModifyListBearerModRes, aper.Snapshot,

	)
	compare func(ERABModifyListBearerModRes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyListBearerModResValueCodec) New(value ERABModifyListBearerModRes,

) (ERABModifyListBearerModResAPERValue, error) {
	if c.encode == nil {
		return ERABModifyListBearerModResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyListBearerModResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyListBearerModResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyListBearerModResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyListBearerModResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyListBearerModResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyListBearerModResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyListBearerModResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyListBearerModResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyListBearerModResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyListBearerModResValueCodec) EncodeAPER(value ERABModifyListBearerModResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyListBearerModResValueCodec) encodeBudgetValue(value ERABModifyListBearerModRes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyListBearerModResValueCodec) encodeChanged(value ERABModifyListBearerModRes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding is the concrete IEBinding[ERABNotToBeModifiedItemBearerModInd, ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding struct {
	info   s00.FieldInfo
	codec  ERABNotToBeModifiedItemBearerModIndValueCodec
	inject func(ERABNotToBeModifiedItemBearerModInd,

	) ERABNotToBeModifiedItemBearerModIndIEValue

	get func(*ERABNotToBeModifiedItemBearerModIndIEValue,

	) (*ERABNotToBeModifiedItemBearerModInd,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) Codec() ERABNotToBeModifiedItemBearerModIndValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) New(value ERABNotToBeModifiedItemBearerModInd,

) (ERABNotToBeModifiedItemBearerModIndIEField, error) {
	if b.inject == nil {
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) Get(field *ERABNotToBeModifiedItemBearerModIndIEField) (*ERABNotToBeModifiedItemBearerModInd,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABNotToBeModifiedItemBearerModIndValueCodec is the concrete ValueCodec[ERABNotToBeModifiedItemBearerModInd].
type ERABNotToBeModifiedItemBearerModIndValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModInd,

		error)
	encode func(ERABNotToBeModifiedItemBearerModInd,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModInd, aper.DecodeState,

	) (ERABNotToBeModifiedItemBearerModInd, aper.Snapshot,

	)
	compare func(ERABNotToBeModifiedItemBearerModInd, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndValueCodec) New(value ERABNotToBeModifiedItemBearerModInd,

) (ERABNotToBeModifiedItemBearerModIndAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModInd,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModInd,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEField is the concrete ProtocolIEField[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABNotToBeModifiedItemBearerModIndIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEField) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABNotToBeModifiedItemBearerModIndIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABNotToBeModifiedItemBearerModIndIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABNotToBeModifiedItemBearerModIndIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABNotToBeModifiedItemBearerModIndIEField{}
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
	var zero ERABNotToBeModifiedItemBearerModIndIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding is the concrete IEBinding[ERABReleaseItemBearerRelComp, ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding struct {
	info   s00.FieldInfo
	codec  ERABReleaseItemBearerRelCompValueCodec
	inject func(ERABReleaseItemBearerRelComp,

	) ERABReleaseItemBearerRelCompIEValue

	get func(*ERABReleaseItemBearerRelCompIEValue,

	) (*ERABReleaseItemBearerRelComp,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) Codec() ERABReleaseItemBearerRelCompValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) New(value ERABReleaseItemBearerRelComp,

) (ERABReleaseItemBearerRelCompIEField, error) {
	if b.inject == nil {
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) Get(field *ERABReleaseItemBearerRelCompIEField) (*ERABReleaseItemBearerRelComp,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseItemBearerRelCompValueCodec is the concrete ValueCodec[ERABReleaseItemBearerRelComp].
type ERABReleaseItemBearerRelCompValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelComp,

		error)
	encode func(ERABReleaseItemBearerRelComp,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelComp, aper.DecodeState,

	) (ERABReleaseItemBearerRelComp, aper.Snapshot,

	)
	compare func(ERABReleaseItemBearerRelComp, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompValueCodec) New(value ERABReleaseItemBearerRelComp,

) (ERABReleaseItemBearerRelCompAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelComp,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompValueCodec) encodeChanged(value ERABReleaseItemBearerRelComp,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEField is the concrete ProtocolIEField[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABReleaseItemBearerRelCompIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEField) WithoutReplay() ERABReleaseItemBearerRelCompIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABReleaseItemBearerRelCompIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABReleaseItemBearerRelCompIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABReleaseItemBearerRelCompIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseItemBearerRelCompIEField{}
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
	var zero ERABReleaseItemBearerRelCompIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABReleaseListBearerRelCompValueCodec is the concrete ValueCodec[ERABReleaseListBearerRelComp].
type ERABReleaseListBearerRelCompValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseListBearerRelComp,

		error)
	encode func(ERABReleaseListBearerRelComp,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseListBearerRelComp, aper.DecodeState,

	) (ERABReleaseListBearerRelComp, aper.Snapshot,

	)
	compare func(ERABReleaseListBearerRelComp, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseListBearerRelCompValueCodec) New(value ERABReleaseListBearerRelComp,

) (ERABReleaseListBearerRelCompAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseListBearerRelCompAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseListBearerRelCompAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseListBearerRelCompAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseListBearerRelCompAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseListBearerRelCompValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseListBearerRelCompAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseListBearerRelCompAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseListBearerRelCompAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseListBearerRelCompAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseListBearerRelCompAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseListBearerRelCompValueCodec) EncodeAPER(value ERABReleaseListBearerRelCompAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseListBearerRelCompValueCodec) encodeBudgetValue(value ERABReleaseListBearerRelComp,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseListBearerRelCompValueCodec) encodeChanged(value ERABReleaseListBearerRelComp,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding is the concrete IEBinding[ERABSetupItemBearerSURes, ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding struct {
	info   s00.FieldInfo
	codec  ERABSetupItemBearerSUResValueCodec
	inject func(ERABSetupItemBearerSURes,

	) ERABSetupItemBearerSUResIEValue

	get func(*ERABSetupItemBearerSUResIEValue,

	) (*ERABSetupItemBearerSURes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) Codec() ERABSetupItemBearerSUResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) New(value ERABSetupItemBearerSURes,

) (ERABSetupItemBearerSUResIEField, error) {
	if b.inject == nil {
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupItemBearerSUResIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) Get(field *ERABSetupItemBearerSUResIEField) (*ERABSetupItemBearerSURes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupItemBearerSUResValueCodec is the concrete ValueCodec[ERABSetupItemBearerSURes].
type ERABSetupItemBearerSUResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSURes,

		error)
	encode func(ERABSetupItemBearerSURes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSURes, aper.DecodeState,

	) (ERABSetupItemBearerSURes, aper.Snapshot,

	)
	compare func(ERABSetupItemBearerSURes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResValueCodec) New(value ERABSetupItemBearerSURes,

) (ERABSetupItemBearerSUResAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResValueCodec) EncodeAPER(value ERABSetupItemBearerSUResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResValueCodec) encodeBudgetValue(value ERABSetupItemBearerSURes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResValueCodec) encodeChanged(value ERABSetupItemBearerSURes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEField is the concrete ProtocolIEField[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABSetupItemBearerSUResIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEField) WithoutReplay() ERABSetupItemBearerSUResIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemBearerSUResIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemBearerSUResIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABSetupItemBearerSUResIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemBearerSUResIEField{}
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
	var zero ERABSetupItemBearerSUResIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding is the concrete IEBinding[ERABSetupItemCtxtSURes, ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding struct {
	info   s00.FieldInfo
	codec  ERABSetupItemCtxtSUResValueCodec
	inject func(ERABSetupItemCtxtSURes,

	) ERABSetupItemCtxtSUResIEValue

	get func(*ERABSetupItemCtxtSUResIEValue,

	) (*ERABSetupItemCtxtSURes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) Codec() ERABSetupItemCtxtSUResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) New(value ERABSetupItemCtxtSURes,

) (ERABSetupItemCtxtSUResIEField, error) {
	if b.inject == nil {
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABSetupItemCtxtSUResIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) Get(field *ERABSetupItemCtxtSUResIEField) (*ERABSetupItemCtxtSURes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABSetupItemCtxtSUResValueCodec is the concrete ValueCodec[ERABSetupItemCtxtSURes].
type ERABSetupItemCtxtSUResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSURes,

		error)
	encode func(ERABSetupItemCtxtSURes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSURes, aper.DecodeState,

	) (ERABSetupItemCtxtSURes, aper.Snapshot,

	)
	compare func(ERABSetupItemCtxtSURes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResValueCodec) New(value ERABSetupItemCtxtSURes,

) (ERABSetupItemCtxtSUResAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSURes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResValueCodec) encodeChanged(value ERABSetupItemCtxtSURes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEField is the concrete ProtocolIEField[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABSetupItemCtxtSUResIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEField) WithoutReplay() ERABSetupItemCtxtSUResIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABSetupItemCtxtSUResIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABSetupItemCtxtSUResIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABSetupItemCtxtSUResIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemCtxtSUResIEField{}
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
	var zero ERABSetupItemCtxtSUResIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
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

// ERABFailedtoSetupListHOReqAckValueCodec is the concrete ValueCodec[ERABFailedtoSetupListHOReqAck].
type ERABFailedtoSetupListHOReqAckValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupListHOReqAck,

		error)
	encode func(ERABFailedtoSetupListHOReqAck,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupListHOReqAck, aper.DecodeState,

	) (ERABFailedtoSetupListHOReqAck, aper.Snapshot,

	)
	compare func(ERABFailedtoSetupListHOReqAck, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupListHOReqAckValueCodec) New(value ERABFailedtoSetupListHOReqAck,

) (ERABFailedtoSetupListHOReqAckAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupListHOReqAckAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupListHOReqAckAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupListHOReqAckAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupListHOReqAckAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupListHOReqAckValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupListHOReqAckAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupListHOReqAckAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupListHOReqAckAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupListHOReqAckAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupListHOReqAckAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupListHOReqAckValueCodec) EncodeAPER(value ERABFailedtoSetupListHOReqAckAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupListHOReqAckValueCodec) encodeBudgetValue(value ERABFailedtoSetupListHOReqAck,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupListHOReqAckValueCodec) encodeChanged(value ERABFailedtoSetupListHOReqAck,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// ERABFailedToResumeListResumeResValueCodec is the concrete ValueCodec[ERABFailedToResumeListResumeRes].
type ERABFailedToResumeListResumeResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s15.ERABFailedToResumeListResumeRes,

		error)
	encode func(s15.ERABFailedToResumeListResumeRes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s15.ERABFailedToResumeListResumeRes, aper.DecodeState,

	) (s15.ERABFailedToResumeListResumeRes, aper.Snapshot,

	)
	compare func(s15.ERABFailedToResumeListResumeRes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedToResumeListResumeResValueCodec) New(value s15.ERABFailedToResumeListResumeRes,

) (s15.ERABFailedToResumeListResumeResAPERValue, error) {
	if c.encode == nil {
		return s15.ERABFailedToResumeListResumeResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s15.ERABFailedToResumeListResumeResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s15.ERABFailedToResumeListResumeResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s15.ERABFailedToResumeListResumeResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedToResumeListResumeResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s15.ERABFailedToResumeListResumeResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s15.ERABFailedToResumeListResumeResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s15.ERABFailedToResumeListResumeResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s15.ERABFailedToResumeListResumeResAPERValue {
			sealed := s15.ERABFailedToResumeListResumeResAPERValue{Value: value}
			*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReplay(&sealed) = replay
			*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s15.ERABFailedToResumeListResumeResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedToResumeListResumeResValueCodec) EncodeAPER(value s15.ERABFailedToResumeListResumeResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s15.BridgeERABFailedToResumeListResumeResAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s15.BridgeERABFailedToResumeListResumeResAPERValueFieldContext(&value) == c.context && !fresh && (*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s15.BridgeERABFailedToResumeListResumeResAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABFailedToResumeListResumeResValueCodec) encodeBudgetValue(value s15.ERABFailedToResumeListResumeRes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedToResumeListResumeResValueCodec) encodeChanged(value s15.ERABFailedToResumeListResumeRes,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEContainer is the concrete ProtocolIEContainer[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEContainer []ERABFailedtoSetupItemHOReqAckIEField

// ERABItemIEContainer is the concrete ProtocolIEContainer[ERABItemIEValue].
type ERABItemIEContainer []ERABItemIEField

// ERABModifyItemBearerModConfIEContainer is the concrete ProtocolIEContainer[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEContainer []ERABModifyItemBearerModConfIEField

// ERABModifyItemBearerModResIEContainer is the concrete ProtocolIEContainer[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEContainer []ERABModifyItemBearerModResIEField

// ERABNotToBeModifiedItemBearerModIndIEContainer is the concrete ProtocolIEContainer[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEContainer []ERABNotToBeModifiedItemBearerModIndIEField

// ERABReleaseItemBearerRelCompIEContainer is the concrete ProtocolIEContainer[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEContainer []ERABReleaseItemBearerRelCompIEField

// ERABSetupItemBearerSUResIEContainer is the concrete ProtocolIEContainer[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEContainer []ERABSetupItemBearerSUResIEField

// ERABSetupItemCtxtSUResIEContainer is the concrete ProtocolIEContainer[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEContainer []ERABSetupItemCtxtSUResIEField

// ERABItemAPERValue is the concrete APERValue[ERABItem].
type ERABItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemAPERValue) WithoutReplay() ERABItemAPERValue {
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

// ERABFailedToSetupItemHOReqAckAPERValue is the concrete APERValue[ERABFailedToSetupItemHOReqAck].
type ERABFailedToSetupItemHOReqAckAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABFailedToSetupItemHOReqAck

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedToSetupItemHOReqAckAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedToSetupItemHOReqAckAPERValue) WithoutReplay() ERABFailedToSetupItemHOReqAckAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyListBearerModConfAPERValue is the concrete APERValue[ERABModifyListBearerModConf].
type ERABModifyListBearerModConfAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyListBearerModConf

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyListBearerModConfAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyListBearerModConfAPERValue) WithoutReplay() ERABModifyListBearerModConfAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABListAPERValue is the concrete APERValue[ERABList].
type ERABListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABListAPERValue) WithoutReplay() ERABListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedListBearerModIndAPERValue is the concrete APERValue[ERABNotToBeModifiedListBearerModInd].
type ERABNotToBeModifiedListBearerModIndAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABNotToBeModifiedListBearerModInd

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedListBearerModIndAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedListBearerModIndAPERValue) WithoutReplay() ERABNotToBeModifiedListBearerModIndAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfAPERValue is the concrete APERValue[ERABModifyItemBearerModConf].
type ERABModifyItemBearerModConfAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyItemBearerModConf

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfAPERValue) WithoutReplay() ERABModifyItemBearerModConfAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResAPERValue is the concrete APERValue[ERABModifyItemBearerModRes].
type ERABModifyItemBearerModResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyItemBearerModRes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResAPERValue) WithoutReplay() ERABModifyItemBearerModResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyListBearerModResAPERValue is the concrete APERValue[ERABModifyListBearerModRes].
type ERABModifyListBearerModResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABModifyListBearerModRes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyListBearerModResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyListBearerModResAPERValue) WithoutReplay() ERABModifyListBearerModResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndAPERValue is the concrete APERValue[ERABNotToBeModifiedItemBearerModInd].
type ERABNotToBeModifiedItemBearerModIndAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABNotToBeModifiedItemBearerModInd

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompAPERValue is the concrete APERValue[ERABReleaseItemBearerRelComp].
type ERABReleaseItemBearerRelCompAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseItemBearerRelComp

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseListBearerRelCompAPERValue is the concrete APERValue[ERABReleaseListBearerRelComp].
type ERABReleaseListBearerRelCompAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseListBearerRelComp

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseListBearerRelCompAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseListBearerRelCompAPERValue) WithoutReplay() ERABReleaseListBearerRelCompAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResAPERValue is the concrete APERValue[ERABSetupItemBearerSURes].
type ERABSetupItemBearerSUResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupItemBearerSURes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResAPERValue) WithoutReplay() ERABSetupItemBearerSUResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResAPERValue is the concrete APERValue[ERABSetupItemCtxtSURes].
type ERABSetupItemCtxtSUResAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupItemCtxtSURes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResAPERValue) WithoutReplay() ERABSetupItemCtxtSUResAPERValue {
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

// ERABFailedtoSetupListHOReqAckAPERValue is the concrete APERValue[ERABFailedtoSetupListHOReqAck].
type ERABFailedtoSetupListHOReqAckAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABFailedtoSetupListHOReqAck

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupListHOReqAckAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupListHOReqAckAPERValue) WithoutReplay() ERABFailedtoSetupListHOReqAckAPERValue {
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

// ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, error)
	encode  func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) New(value ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) encodeChanged(value ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList []ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer

// ERABItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABItemIEValue]].
type ERABItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemIEValueERABIEContainerList, error)
	encode  func(ERABItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemIEValueERABIEContainerList, aper.DecodeState) (ERABItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemIEValueERABIEContainerListValueCodec) New(value ERABItemIEValueERABIEContainerList) (ERABItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemIEValueERABIEContainerListValueCodec) encodeChanged(value ERABItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABItemIEValue].
type ERABItemIEValueERABIEContainerList []ERABItemIEValueProtocolIESingleContainer

// ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueERABIEContainerList, error)
	encode  func(ERABModifyItemBearerModConfIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) New(value ERABModifyItemBearerModConfIEValueERABIEContainerList) (ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModConfIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueERABIEContainerList []ERABModifyItemBearerModConfIEValueProtocolIESingleContainer

// ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueERABIEContainerList, error)
	encode  func(ERABModifyItemBearerModResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResIEValueERABIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) New(value ERABModifyItemBearerModResIEValueERABIEContainerList) (ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueERABIEContainerList []ERABModifyItemBearerModResIEValueProtocolIESingleContainer

// ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) New(value ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList []ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueERABIEContainerList, error)
	encode  func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) New(value ERABReleaseItemBearerRelCompIEValueERABIEContainerList) (ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueERABIEContainerList []ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer

// ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueERABIEContainerList, error)
	encode  func(ERABSetupItemBearerSUResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) New(value ERABSetupItemBearerSUResIEValueERABIEContainerList) (ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) encodeChanged(value ERABSetupItemBearerSUResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueERABIEContainerList []ERABSetupItemBearerSUResIEValueProtocolIESingleContainer

// ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueERABIEContainerList, error)
	encode  func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) New(value ERABSetupItemCtxtSUResIEValueERABIEContainerList) (ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) encodeChanged(value ERABSetupItemCtxtSUResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEValueERABIEContainerList is the concrete ERABIEContainerList[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueERABIEContainerList []ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer

// ERABFailedtoSetupItemHOReqAckIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEField, error)
	encode  func(ERABFailedtoSetupItemHOReqAckIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupItemHOReqAckIEField, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot)
	compare func(ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) New(value ERABFailedtoSetupItemHOReqAckIEField) (ERABFailedtoSetupItemHOReqAckIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupItemHOReqAckIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupItemHOReqAckIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) EncodeAPER(value ERABFailedtoSetupItemHOReqAckIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) encodeBudgetValue(value ERABFailedtoSetupItemHOReqAckIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) encodeChanged(value ERABFailedtoSetupItemHOReqAckIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABItemIEValue]].
type ERABItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemIEField, error)
	encode  func(ERABItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemIEField, aper.DecodeState) (ERABItemIEField, aper.Snapshot)
	compare func(ERABItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemIEFieldValueCodec) New(value ERABItemIEField) (ERABItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemIEFieldValueCodec) EncodeAPER(value ERABItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemIEFieldValueCodec) encodeBudgetValue(value ERABItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemIEFieldValueCodec) encodeChanged(value ERABItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEField, error)
	encode  func(ERABModifyItemBearerModConfIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfIEField, aper.DecodeState) (ERABModifyItemBearerModConfIEField, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfIEFieldValueCodec) New(value ERABModifyItemBearerModConfIEField) (ERABModifyItemBearerModConfIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfIEFieldValueCodec) EncodeAPER(value ERABModifyItemBearerModConfIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfIEFieldValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfIEFieldValueCodec) encodeChanged(value ERABModifyItemBearerModConfIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEField, error)
	encode  func(ERABModifyItemBearerModResIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResIEField, aper.DecodeState) (ERABModifyItemBearerModResIEField, aper.Snapshot)
	compare func(ERABModifyItemBearerModResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResIEFieldValueCodec) New(value ERABModifyItemBearerModResIEField) (ERABModifyItemBearerModResIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResIEFieldValueCodec) EncodeAPER(value ERABModifyItemBearerModResIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResIEFieldValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResIEFieldValueCodec) encodeChanged(value ERABModifyItemBearerModResIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEField, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndIEField, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) New(value ERABNotToBeModifiedItemBearerModIndIEField) (ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEField, error)
	encode  func(ERABReleaseItemBearerRelCompIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompIEField, aper.DecodeState) (ERABReleaseItemBearerRelCompIEField, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompIEFieldValueCodec) New(value ERABReleaseItemBearerRelCompIEField) (ERABReleaseItemBearerRelCompIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompIEFieldValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompIEFieldValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompIEFieldValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEField, error)
	encode  func(ERABSetupItemBearerSUResIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResIEField, aper.DecodeState) (ERABSetupItemBearerSUResIEField, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResIEFieldValueCodec) New(value ERABSetupItemBearerSUResIEField) (ERABSetupItemBearerSUResIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResIEFieldValueCodec) EncodeAPER(value ERABSetupItemBearerSUResIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResIEFieldValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResIEFieldValueCodec) encodeChanged(value ERABSetupItemBearerSUResIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEField, error)
	encode  func(ERABSetupItemCtxtSUResIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResIEField, aper.DecodeState) (ERABSetupItemCtxtSUResIEField, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResIEFieldValueCodec) New(value ERABSetupItemCtxtSUResIEField) (ERABSetupItemCtxtSUResIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResIEFieldValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResIEFieldValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResIEFieldValueCodec) encodeChanged(value ERABSetupItemCtxtSUResIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEContainer, error)
	encode  func(ERABFailedtoSetupItemHOReqAckIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupItemHOReqAckIEContainer, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot)
	compare func(ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) New(value ERABFailedtoSetupItemHOReqAckIEContainer) (ERABFailedtoSetupItemHOReqAckIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupItemHOReqAckIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupItemHOReqAckIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) EncodeAPER(value ERABFailedtoSetupItemHOReqAckIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) encodeBudgetValue(value ERABFailedtoSetupItemHOReqAckIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) encodeChanged(value ERABFailedtoSetupItemHOReqAckIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABItemIEValue]].
type ERABItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemIEContainer, error)
	encode  func(ERABItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemIEContainer, aper.DecodeState) (ERABItemIEContainer, aper.Snapshot)
	compare func(ERABItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemIEContainerValueCodec) New(value ERABItemIEContainer) (ERABItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemIEContainerValueCodec) EncodeAPER(value ERABItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemIEContainerValueCodec) encodeBudgetValue(value ERABItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemIEContainerValueCodec) encodeChanged(value ERABItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEContainer, error)
	encode  func(ERABModifyItemBearerModConfIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfIEContainer, aper.DecodeState) (ERABModifyItemBearerModConfIEContainer, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfIEContainerValueCodec) New(value ERABModifyItemBearerModConfIEContainer) (ERABModifyItemBearerModConfIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfIEContainerValueCodec) EncodeAPER(value ERABModifyItemBearerModConfIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfIEContainerValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfIEContainerValueCodec) encodeChanged(value ERABModifyItemBearerModConfIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEContainer, error)
	encode  func(ERABModifyItemBearerModResIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResIEContainer, aper.DecodeState) (ERABModifyItemBearerModResIEContainer, aper.Snapshot)
	compare func(ERABModifyItemBearerModResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResIEContainerValueCodec) New(value ERABModifyItemBearerModResIEContainer) (ERABModifyItemBearerModResIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResIEContainerValueCodec) EncodeAPER(value ERABModifyItemBearerModResIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResIEContainerValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResIEContainerValueCodec) encodeChanged(value ERABModifyItemBearerModResIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEContainer, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndIEContainer, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) New(value ERABNotToBeModifiedItemBearerModIndIEContainer) (ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEContainer, error)
	encode  func(ERABReleaseItemBearerRelCompIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompIEContainer, aper.DecodeState) (ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompIEContainerValueCodec) New(value ERABReleaseItemBearerRelCompIEContainer) (ERABReleaseItemBearerRelCompIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompIEContainerValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompIEContainerValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompIEContainerValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEContainer, error)
	encode  func(ERABSetupItemBearerSUResIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResIEContainer, aper.DecodeState) (ERABSetupItemBearerSUResIEContainer, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResIEContainerValueCodec) New(value ERABSetupItemBearerSUResIEContainer) (ERABSetupItemBearerSUResIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResIEContainerValueCodec) EncodeAPER(value ERABSetupItemBearerSUResIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResIEContainerValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResIEContainerValueCodec) encodeChanged(value ERABSetupItemBearerSUResIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEContainer, error)
	encode  func(ERABSetupItemCtxtSUResIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResIEContainer, aper.DecodeState) (ERABSetupItemCtxtSUResIEContainer, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResIEContainerValueCodec) New(value ERABSetupItemCtxtSUResIEContainer) (ERABSetupItemCtxtSUResIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResIEContainerValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResIEContainerValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResIEContainerValueCodec) encodeChanged(value ERABSetupItemCtxtSUResIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) New(value ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList []ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer

// ERABItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABItemIEValue]].
type ERABItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemIEValueProtocolErrorIEContainerListValueCodec) New(value ERABItemIEValueProtocolErrorIEContainerList) (ERABItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABItemIEValue].
type ERABItemIEValueProtocolErrorIEContainerList []ERABItemIEValueProtocolIESingleContainer

// ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList []ERABModifyItemBearerModConfIEValueProtocolIESingleContainer

// ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList []ERABModifyItemBearerModResIEValueProtocolIESingleContainer

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) New(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList []ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) New(value ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList []ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer

// ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) New(value ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList []ERABSetupItemBearerSUResIEValueProtocolIESingleContainer

// ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) New(value ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList []ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer

// ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, error)
	encode  func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) New(value ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList []ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer

// ERABItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABItemIEValue]].
type ERABItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABItemIEValueProtocolIEContainerList, error)
	encode  func(ERABItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABItemIEValueProtocolIEContainerListValueCodec) New(value ERABItemIEValueProtocolIEContainerList) (ERABItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABItemIEValue].
type ERABItemIEValueProtocolIEContainerList []ERABItemIEValueProtocolIESingleContainer

// ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolIEContainerList, error)
	encode  func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) New(value ERABModifyItemBearerModConfIEValueProtocolIEContainerList) (ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModConfIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModConfIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModConfIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABModifyItemBearerModConfIEValue].
type ERABModifyItemBearerModConfIEValueProtocolIEContainerList []ERABModifyItemBearerModConfIEValueProtocolIESingleContainer

// ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolIEContainerList, error)
	encode  func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) New(value ERABModifyItemBearerModResIEValueProtocolIEContainerList) (ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModifyItemBearerModResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModifyItemBearerModResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModifyItemBearerModResIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABModifyItemBearerModResIEValue].
type ERABModifyItemBearerModResIEValueProtocolIEContainerList []ERABModifyItemBearerModResIEValueProtocolIESingleContainer

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error)
	encode  func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) New(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList []ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, error)
	encode  func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) New(value ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABReleaseItemBearerRelCompIEValue].
type ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList []ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer

// ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolIEContainerList, error)
	encode  func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) New(value ERABSetupItemBearerSUResIEValueProtocolIEContainerList) (ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemBearerSUResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABSetupItemBearerSUResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemBearerSUResIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABSetupItemBearerSUResIEValue].
type ERABSetupItemBearerSUResIEValueProtocolIEContainerList []ERABSetupItemBearerSUResIEValueProtocolIESingleContainer

// ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, error)
	encode  func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) New(value ERABSetupItemCtxtSUResIEValueProtocolIEContainerList) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupItemCtxtSUResIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ERABSetupItemCtxtSUResIEValue].
type ERABSetupItemCtxtSUResIEValueProtocolIEContainerList []ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer

// ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABItemIEValue]].
type ERABItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEValueERABIEContainerListAPERValue) WithoutReplay() ERABItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) WithoutReplay() ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) WithoutReplay() ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedtoSetupItemHOReqAckIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedtoSetupItemHOReqAckIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABItemIEValue]].
type ERABItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEFieldAPERValue) WithoutReplay() ERABItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEFieldAPERValue) WithoutReplay() ERABModifyItemBearerModConfIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEFieldAPERValue) WithoutReplay() ERABModifyItemBearerModResIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEFieldAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEFieldAPERValue) WithoutReplay() ERABSetupItemBearerSUResIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEFieldAPERValue) WithoutReplay() ERABSetupItemCtxtSUResIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedtoSetupItemHOReqAckIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedtoSetupItemHOReqAckIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABItemIEValue]].
type ERABItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEContainerAPERValue) WithoutReplay() ERABItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEContainerAPERValue) WithoutReplay() ERABModifyItemBearerModConfIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEContainerAPERValue) WithoutReplay() ERABModifyItemBearerModResIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEContainerAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEContainerAPERValue) WithoutReplay() ERABSetupItemBearerSUResIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEContainerAPERValue) WithoutReplay() ERABSetupItemCtxtSUResIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABItemIEValue]].
type ERABItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABFailedtoSetupItemHOReqAckIEValue]].
type ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABItemIEValue]].
type ERABItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABModifyItemBearerModConfIEValue]].
type ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModConfIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABModifyItemBearerModResIEValue]].
type ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModifyItemBearerModResIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABNotToBeModifiedItemBearerModIndIEValue]].
type ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABReleaseItemBearerRelCompIEValue]].
type ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABSetupItemBearerSUResIEValue]].
type ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemBearerSUResIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ERABSetupItemCtxtSUResIEValue]].
type ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABSetupItemCtxtSUResIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABFailedToSetupItemHOReqAck(v *ERABFailedToSetupItemHOReqAck, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s14.BridgeCaptureS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToSetupItemHOReqAckExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedToSetupItemHOReqAck(v *ERABFailedToSetupItemHOReqAck, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s14.BridgeCompareS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABFailedToSetupItemHOReqAckExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABFailedtoSetupItemHOReqAckIEValue(v *ERABFailedtoSetupItemHOReqAckIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(21):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedtoSetupItemHOReqAck == nil)
				if v.rowERABFailedtoSetupItemHOReqAck != nil {
					BridgeCaptureS1APERABFailedToSetupItemHOReqAck(v.rowERABFailedtoSetupItemHOReqAck, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedtoSetupItemHOReqAckIEValue) captureSemantics(s aper.SemanticCapture) ERABFailedtoSetupItemHOReqAckIEValue {
	BridgeCaptureS1APERABFailedtoSetupItemHOReqAckIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABFailedtoSetupItemHOReqAckIEValue(v *ERABFailedtoSetupItemHOReqAckIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(21):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedtoSetupItemHOReqAck == nil)
				if v.rowERABFailedtoSetupItemHOReqAck != nil {
					BridgeCompareS1APERABFailedToSetupItemHOReqAck(v.rowERABFailedtoSetupItemHOReqAck, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABFailedtoSetupItemHOReqAckIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABFailedtoSetupItemHOReqAckIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABItem(v *ERABItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s14.BridgeCaptureS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABItem(v *ERABItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s14.BridgeCompareS1APCause(&v.Cause, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABItemIEValue(v *ERABItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(35):
			{
				f := s.Begin()
				s.Bool(v.rowERABItem == nil)
				if v.rowERABItem != nil {
					BridgeCaptureS1APERABItem(v.rowERABItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABItemIEValue) captureSemantics(s aper.SemanticCapture) ERABItemIEValue {
	BridgeCaptureS1APERABItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABItemIEValue(v *ERABItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(35):
			{
				f := s.Begin()
				s.Bool(v.rowERABItem == nil)
				if v.rowERABItem != nil {
					BridgeCompareS1APERABItem(v.rowERABItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABModifyItemBearerModConf(v *ERABModifyItemBearerModConf, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABModifyItemBearerModConfExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyItemBearerModConf(v *ERABModifyItemBearerModConf, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABModifyItemBearerModConfExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModifyItemBearerModConfIEValue(v *ERABModifyItemBearerModConfIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(204):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyItemBearerModConf == nil)
				if v.rowERABModifyItemBearerModConf != nil {
					BridgeCaptureS1APERABModifyItemBearerModConf(v.rowERABModifyItemBearerModConf, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyItemBearerModConfIEValue) captureSemantics(s aper.SemanticCapture) ERABModifyItemBearerModConfIEValue {
	BridgeCaptureS1APERABModifyItemBearerModConfIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModifyItemBearerModConfIEValue(v *ERABModifyItemBearerModConfIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(204):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyItemBearerModConf == nil)
				if v.rowERABModifyItemBearerModConf != nil {
					BridgeCompareS1APERABModifyItemBearerModConf(v.rowERABModifyItemBearerModConf, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyItemBearerModConfIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModifyItemBearerModConfIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABModifyItemBearerModRes(v *ERABModifyItemBearerModRes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABModifyItemBearerModResExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABModifyItemBearerModRes(v *ERABModifyItemBearerModRes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABModifyItemBearerModResExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABModifyItemBearerModResIEValue(v *ERABModifyItemBearerModResIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(37):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyItemBearerModRes == nil)
				if v.rowERABModifyItemBearerModRes != nil {
					BridgeCaptureS1APERABModifyItemBearerModRes(v.rowERABModifyItemBearerModRes, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyItemBearerModResIEValue) captureSemantics(s aper.SemanticCapture) ERABModifyItemBearerModResIEValue {
	BridgeCaptureS1APERABModifyItemBearerModResIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModifyItemBearerModResIEValue(v *ERABModifyItemBearerModResIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(37):
			{
				f := s.Begin()
				s.Bool(v.rowERABModifyItemBearerModRes == nil)
				if v.rowERABModifyItemBearerModRes != nil {
					BridgeCompareS1APERABModifyItemBearerModRes(v.rowERABModifyItemBearerModRes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModifyItemBearerModResIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModifyItemBearerModResIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABNotToBeModifiedItemBearerModInd(v *ERABNotToBeModifiedItemBearerModInd, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.DLGTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABNotToBeModifiedItemBearerModInd(v *ERABNotToBeModifiedItemBearerModInd, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.DLGTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABNotToBeModifiedItemBearerModIndIEValue(v *ERABNotToBeModifiedItemBearerModIndIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(202):
			{
				f := s.Begin()
				s.Bool(v.rowERABNotToBeModifiedItemBearerModInd == nil)
				if v.rowERABNotToBeModifiedItemBearerModInd != nil {
					BridgeCaptureS1APERABNotToBeModifiedItemBearerModInd(v.rowERABNotToBeModifiedItemBearerModInd, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABNotToBeModifiedItemBearerModIndIEValue) captureSemantics(s aper.SemanticCapture) ERABNotToBeModifiedItemBearerModIndIEValue {
	BridgeCaptureS1APERABNotToBeModifiedItemBearerModIndIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABNotToBeModifiedItemBearerModIndIEValue(v *ERABNotToBeModifiedItemBearerModIndIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(202):
			{
				f := s.Begin()
				s.Bool(v.rowERABNotToBeModifiedItemBearerModInd == nil)
				if v.rowERABNotToBeModifiedItemBearerModInd != nil {
					BridgeCompareS1APERABNotToBeModifiedItemBearerModInd(v.rowERABNotToBeModifiedItemBearerModInd, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABNotToBeModifiedItemBearerModIndIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABNotToBeModifiedItemBearerModIndIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABReleaseItemBearerRelComp(v *ERABReleaseItemBearerRelComp, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABReleaseItemBearerRelCompExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseItemBearerRelComp(v *ERABReleaseItemBearerRelComp, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABReleaseItemBearerRelCompExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABReleaseItemBearerRelCompIEValue(v *ERABReleaseItemBearerRelCompIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleaseItemBearerRelComp == nil)
				if v.rowERABReleaseItemBearerRelComp != nil {
					BridgeCaptureS1APERABReleaseItemBearerRelComp(v.rowERABReleaseItemBearerRelComp, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseItemBearerRelCompIEValue) captureSemantics(s aper.SemanticCapture) ERABReleaseItemBearerRelCompIEValue {
	BridgeCaptureS1APERABReleaseItemBearerRelCompIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABReleaseItemBearerRelCompIEValue(v *ERABReleaseItemBearerRelCompIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowERABReleaseItemBearerRelComp == nil)
				if v.rowERABReleaseItemBearerRelComp != nil {
					BridgeCompareS1APERABReleaseItemBearerRelComp(v.rowERABReleaseItemBearerRelComp, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABReleaseItemBearerRelCompIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABReleaseItemBearerRelCompIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABSetupItemBearerSURes(v *ERABSetupItemBearerSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSetupItemBearerSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupItemBearerSURes(v *ERABSetupItemBearerSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSetupItemBearerSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupItemBearerSUResIEValue(v *ERABSetupItemBearerSUResIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(39):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupItemBearerSURes == nil)
				if v.rowERABSetupItemBearerSURes != nil {
					BridgeCaptureS1APERABSetupItemBearerSURes(v.rowERABSetupItemBearerSURes, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupItemBearerSUResIEValue) captureSemantics(s aper.SemanticCapture) ERABSetupItemBearerSUResIEValue {
	BridgeCaptureS1APERABSetupItemBearerSUResIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABSetupItemBearerSUResIEValue(v *ERABSetupItemBearerSUResIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(39):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupItemBearerSURes == nil)
				if v.rowERABSetupItemBearerSURes != nil {
					BridgeCompareS1APERABSetupItemBearerSURes(v.rowERABSetupItemBearerSURes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupItemBearerSUResIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABSetupItemBearerSUResIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APERABSetupItemCtxtSURes(v *ERABSetupItemCtxtSURes, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s00.BridgeCaptureS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSetupItemCtxtSUResExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupItemCtxtSURes(v *ERABSetupItemCtxtSURes, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	s02.BridgeCompareS1APGTPTEID(&v.GTPTEID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeERABSetupItemCtxtSUResExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupItemCtxtSUResIEValue(v *ERABSetupItemCtxtSUResIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(50):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupItemCtxtSURes == nil)
				if v.rowERABSetupItemCtxtSURes != nil {
					BridgeCaptureS1APERABSetupItemCtxtSURes(v.rowERABSetupItemCtxtSURes, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupItemCtxtSUResIEValue) captureSemantics(s aper.SemanticCapture) ERABSetupItemCtxtSUResIEValue {
	BridgeCaptureS1APERABSetupItemCtxtSUResIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABSetupItemCtxtSUResIEValue(v *ERABSetupItemCtxtSUResIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(50):
			{
				f := s.Begin()
				s.Bool(v.rowERABSetupItemCtxtSURes == nil)
				if v.rowERABSetupItemCtxtSURes != nil {
					BridgeCompareS1APERABSetupItemCtxtSURes(v.rowERABSetupItemCtxtSURes, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABSetupItemCtxtSUResIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABSetupItemCtxtSUResIEValue(&v, &s)
	return s
}

type ERABList = []ERABItemIEValueProtocolIESingleContainer

// ERABItem represents the ASN.1 type E-RABItem (SEQUENCE).
type ERABItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                     `asn1:"tag:0,context,implicit"`
	Cause             s14.Cause                      `asn1:"tag:1,context,explicit"`
	IEExtensions      s08.ERABItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                           `asn1:"-" json:"-"`
	extCount          int64                          `asn1:"-" json:"-"`
	extPresent        []bool                         `asn1:"-" json:"-"`
	extData           [][]byte                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes ERABItem to APER format.
func (v *ERABItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s08.BridgeERABItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABItem from APER format.
func (v *ERABItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABItem{}
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
	if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&v.Cause, bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABItemExtIEsExtField
				if err := s08.BridgeERABItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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
func (v *ERABItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABItem) WithoutReplay() ERABItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABItem")
}
func (v *ERABItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABItem")
}
func (v *ERABItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABItem(v, &s)
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
func (v *ERABItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABItem{}
		return report, aper.OperationError(err, "ERABItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABItem")
}

type ERABSubjecttoDataForwardingList = []s15.ERABDataForwardingItemIEValueProtocolIESingleContainer
type ERABFailedtoSetupListHOReqAck = []ERABFailedtoSetupItemHOReqAckIEValueProtocolIESingleContainer

// ERABFailedToSetupItemHOReqAck represents the ASN.1 type E-RABFailedToSetupItemHOReqAck (SEQUENCE).
type ERABFailedToSetupItemHOReqAck struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                          `asn1:"tag:0,context,implicit"`
	Cause             s14.Cause                                           `asn1:"tag:1,context,explicit"`
	IEExtensions      s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                `asn1:"-" json:"-"`
	extCount          int64                                               `asn1:"-" json:"-"`
	extPresent        []bool                                              `asn1:"-" json:"-"`
	extData           [][]byte                                            `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                   `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                              `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ERABSetupListBearerSURes = []ERABSetupItemBearerSUResIEValueProtocolIESingleContainer

// ERABSetupItemBearerSURes represents the ASN.1 type E-RABSetupItemBearerSURes (SEQUENCE).
type ERABSetupItemBearerSURes struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	ERABID                s00.ERABID                                     `asn1:"tag:0,context,implicit"`
	TransportLayerAddress s00.TransportLayerAddress                      `asn1:"tag:1,context,implicit"`
	GTPTEID               s00.GTPTEID                                    `asn1:"tag:2,context,implicit"`
	IEExtensions          s08.ERABSetupItemBearerSUResExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                           `asn1:"-" json:"-"`
	extCount              int64                                          `asn1:"-" json:"-"`
	extPresent            []bool                                         `asn1:"-" json:"-"`
	extData               [][]byte                                       `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type ERABModifyListBearerModRes = []ERABModifyItemBearerModResIEValueProtocolIESingleContainer

// ERABModifyItemBearerModRes represents the ASN.1 type E-RABModifyItemBearerModRes (SEQUENCE).
type ERABModifyItemBearerModRes struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                       `asn1:"tag:0,context,implicit"`
	IEExtensions      s08.ERABModifyItemBearerModResExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                             `asn1:"-" json:"-"`
	extCount          int64                                            `asn1:"-" json:"-"`
	extPresent        []bool                                           `asn1:"-" json:"-"`
	extData           [][]byte                                         `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ERABReleaseListBearerRelComp = []ERABReleaseItemBearerRelCompIEValueProtocolIESingleContainer

// ERABReleaseItemBearerRelComp represents the ASN.1 type E-RABReleaseItemBearerRelComp (SEQUENCE).
type ERABReleaseItemBearerRelComp struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                         `asn1:"tag:0,context,implicit"`
	IEExtensions      s08.ERABReleaseItemBearerRelCompExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ERABSetupListCtxtSURes = []ERABSetupItemCtxtSUResIEValueProtocolIESingleContainer

// ERABSetupItemCtxtSURes represents the ASN.1 type E-RABSetupItemCtxtSURes (SEQUENCE).
type ERABSetupItemCtxtSURes struct {
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
	IEExtensions          s08.ERABSetupItemCtxtSUResExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                         `asn1:"-" json:"-"`
	extCount              int64                                        `asn1:"-" json:"-"`
	extPresent            []bool                                       `asn1:"-" json:"-"`
	extData               [][]byte                                     `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type ERABNotToBeModifiedListBearerModInd = []ERABNotToBeModifiedItemBearerModIndIEValueProtocolIESingleContainer

// ERABNotToBeModifiedItemBearerModInd represents the ASN.1 type E-RABNotToBeModifiedItemBearerModInd (SEQUENCE).
type ERABNotToBeModifiedItemBearerModInd struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	ERABID                s00.ERABID                                                `asn1:"tag:0,context,implicit"`
	TransportLayerAddress s00.TransportLayerAddress                                 `asn1:"tag:1,context,implicit"`
	DLGTPTEID             s00.GTPTEID                                               `asn1:"tag:2,context,implicit"`
	IEExtensions          s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                                      `asn1:"-" json:"-"`
	extCount              int64                                                     `asn1:"-" json:"-"`
	extPresent            []bool                                                    `asn1:"-" json:"-"`
	extData               [][]byte                                                  `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type ERABModifyListBearerModConf = []ERABModifyItemBearerModConfIEValueProtocolIESingleContainer

// ERABModifyItemBearerModConf represents the ASN.1 type E-RABModifyItemBearerModConf (SEQUENCE).
type ERABModifyItemBearerModConf struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ERABID            s00.ERABID                                        `asn1:"tag:0,context,implicit"`
	IEExtensions      s08.ERABModifyItemBearerModConfExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                              `asn1:"-" json:"-"`
	extCount          int64                                             `asn1:"-" json:"-"`
	extPresent        []bool                                            `asn1:"-" json:"-"`
	extData           [][]byte                                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes ERABFailedToSetupItemHOReqAck to APER format.
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABFailedToSetupItemHOReqAck from APER format.
func (v *ERABFailedToSetupItemHOReqAck) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABFailedToSetupItemHOReqAck with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABFailedToSetupItemHOReqAck) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAck")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAck")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedToSetupItemHOReqAck")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToSetupItemHOReqAck")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABFailedToSetupItemHOReqAck) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABFailedToSetupItemHOReqAck{}
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
	if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&v.Cause, bb); err != nil {
		return runtime.WrapDecodePath(err, "Cause")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABFailedToSetupItemHOReqAckExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABFailedToSetupItemHOReqAckExtIEsExtField
				if err := s08.BridgeERABFailedToSetupItemHOReqAckExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABSetupItemBearerSURes to APER format.
func (v *ERABSetupItemBearerSURes) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSetupItemBearerSURes) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABSetupItemBearerSURes from APER format.
func (v *ERABSetupItemBearerSURes) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupItemBearerSURes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupItemBearerSURes) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemBearerSURes")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemBearerSURes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupItemBearerSURes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemBearerSURes")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABSetupItemBearerSURes) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemBearerSURes{}
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
		tmp_ieextensions := make(s08.ERABSetupItemBearerSUResExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABSetupItemBearerSUResExtIEsExtField
				if err := s08.BridgeERABSetupItemBearerSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABModifyItemBearerModRes to APER format.
func (v *ERABModifyItemBearerModRes) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModifyItemBearerModRes) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABModifyItemBearerModRes from APER format.
func (v *ERABModifyItemBearerModRes) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModifyItemBearerModRes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModifyItemBearerModRes) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModRes")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModRes")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABModifyItemBearerModRes) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModRes{}
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
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABModifyItemBearerModResExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABModifyItemBearerModResExtIEsExtField
				if err := s08.BridgeERABModifyItemBearerModResExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABReleaseItemBearerRelComp to APER format.
func (v *ERABReleaseItemBearerRelComp) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABReleaseItemBearerRelComp from APER format.
func (v *ERABReleaseItemBearerRelComp) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABReleaseItemBearerRelComp with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABReleaseItemBearerRelComp) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelComp")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelComp")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseItemBearerRelComp")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseItemBearerRelComp")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABReleaseItemBearerRelComp) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseItemBearerRelComp{}
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
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABReleaseItemBearerRelCompExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABReleaseItemBearerRelCompExtIEsExtField
				if err := s08.BridgeERABReleaseItemBearerRelCompExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABSetupItemCtxtSURes to APER format.
func (v *ERABSetupItemCtxtSURes) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSetupItemCtxtSURes) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABSetupItemCtxtSURes from APER format.
func (v *ERABSetupItemCtxtSURes) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupItemCtxtSURes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupItemCtxtSURes) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupItemCtxtSURes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupItemCtxtSURes")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABSetupItemCtxtSURes) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupItemCtxtSURes{}
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
		tmp_ieextensions := make(s08.ERABSetupItemCtxtSUResExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABSetupItemCtxtSUResExtIEsExtField
				if err := s08.BridgeERABSetupItemCtxtSUResExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABNotToBeModifiedItemBearerModInd to APER format.
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABNotToBeModifiedItemBearerModInd from APER format.
func (v *ERABNotToBeModifiedItemBearerModInd) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABNotToBeModifiedItemBearerModInd with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABNotToBeModifiedItemBearerModInd) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABNotToBeModifiedItemBearerModInd")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABNotToBeModifiedItemBearerModInd) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABNotToBeModifiedItemBearerModInd{}
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
		tmp_ieextensions := make(s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABNotToBeModifiedItemBearerModIndExtIEsExtField
				if err := s08.BridgeERABNotToBeModifiedItemBearerModIndExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes ERABModifyItemBearerModConf to APER format.
func (v *ERABModifyItemBearerModConf) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABModifyItemBearerModConf) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABModifyItemBearerModConf from APER format.
func (v *ERABModifyItemBearerModConf) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABModifyItemBearerModConf with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABModifyItemBearerModConf) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModConf")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModConf")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABModifyItemBearerModConf")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABModifyItemBearerModConf")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABModifyItemBearerModConf) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModifyItemBearerModConf{}
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
	if opt_ieextensions {
		tmp_ieextensions := make(s08.ERABModifyItemBearerModConfExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ERABModifyItemBearerModConfExtIEsExtField
				if err := s08.BridgeERABModifyItemBearerModConfExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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
func (v *ERABFailedToSetupItemHOReqAck) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedToSetupItemHOReqAck", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedToSetupItemHOReqAck", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedToSetupItemHOReqAck) WithoutReplay() ERABFailedToSetupItemHOReqAck {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedToSetupItemHOReqAck
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyItemBearerModConf) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyItemBearerModConf", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyItemBearerModConf", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyItemBearerModConf) WithoutReplay() ERABModifyItemBearerModConf {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyItemBearerModConf
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABModifyItemBearerModRes) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABModifyItemBearerModRes", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABModifyItemBearerModRes", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABModifyItemBearerModRes) WithoutReplay() ERABModifyItemBearerModRes {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABModifyItemBearerModRes
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABNotToBeModifiedItemBearerModInd) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABNotToBeModifiedItemBearerModInd", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABNotToBeModifiedItemBearerModInd", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABNotToBeModifiedItemBearerModInd) WithoutReplay() ERABNotToBeModifiedItemBearerModInd {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABNotToBeModifiedItemBearerModInd
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABReleaseItemBearerRelComp) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseItemBearerRelComp", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseItemBearerRelComp", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseItemBearerRelComp) WithoutReplay() ERABReleaseItemBearerRelComp {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseItemBearerRelComp
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupItemBearerSURes) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupItemBearerSURes", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupItemBearerSURes", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupItemBearerSURes) WithoutReplay() ERABSetupItemBearerSURes {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupItemBearerSURes
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupItemCtxtSURes) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupItemCtxtSURes", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupItemCtxtSURes", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupItemCtxtSURes) WithoutReplay() ERABSetupItemCtxtSURes {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupItemCtxtSURes
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABFailedToSetupItemHOReqAck) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABFailedToSetupItemHOReqAck) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToSetupItemHOReqAck.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToSetupItemHOReqAck.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABFailedToSetupItemHOReqAck) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABFailedToSetupItemHOReqAck.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABFailedToSetupItemHOReqAck.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModifyItemBearerModConf) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModifyItemBearerModConf) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyItemBearerModConf.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyItemBearerModConf.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModifyItemBearerModConf) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyItemBearerModConf.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyItemBearerModConf.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABModifyItemBearerModRes) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABModifyItemBearerModRes) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyItemBearerModRes.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyItemBearerModRes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABModifyItemBearerModRes) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABModifyItemBearerModRes.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABModifyItemBearerModRes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABNotToBeModifiedItemBearerModInd) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABNotToBeModifiedItemBearerModInd) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABNotToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABNotToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABNotToBeModifiedItemBearerModInd) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABNotToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABNotToBeModifiedItemBearerModInd.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABReleaseItemBearerRelComp) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABReleaseItemBearerRelComp) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseItemBearerRelComp.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseItemBearerRelComp.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABReleaseItemBearerRelComp) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseItemBearerRelComp.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseItemBearerRelComp.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABSetupItemBearerSURes) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSetupItemBearerSURes) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupItemBearerSURes.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupItemBearerSURes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSetupItemBearerSURes) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupItemBearerSURes.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupItemBearerSURes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABSetupItemCtxtSURes) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSetupItemCtxtSURes) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupItemCtxtSURes.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupItemCtxtSURes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSetupItemCtxtSURes) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupItemCtxtSURes.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupItemCtxtSURes.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABFailedToSetupItemHOReqAck) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedToSetupItemHOReqAck")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToSetupItemHOReqAck")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedToSetupItemHOReqAck(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedToSetupItemHOReqAck")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedToSetupItemHOReqAck")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedToSetupItemHOReqAck")
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedToSetupItemHOReqAck")
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedToSetupItemHOReqAck(v, &s)
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
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedToSetupItemHOReqAck) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABModifyItemBearerModConf) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyItemBearerModConf")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyItemBearerModConf) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyItemBearerModConf")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyItemBearerModConf(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyItemBearerModConf")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyItemBearerModConf")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyItemBearerModConf) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyItemBearerModConf")
}
func (v *ERABModifyItemBearerModConf) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyItemBearerModConf")
}
func (v *ERABModifyItemBearerModConf) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyItemBearerModConf(v, &s)
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
func (v *ERABModifyItemBearerModConf) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyItemBearerModConf) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABModifyItemBearerModRes) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABModifyItemBearerModRes")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABModifyItemBearerModRes) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABModifyItemBearerModRes")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABModifyItemBearerModRes(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABModifyItemBearerModRes")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABModifyItemBearerModRes")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABModifyItemBearerModRes) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABModifyItemBearerModRes")
}
func (v *ERABModifyItemBearerModRes) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABModifyItemBearerModRes")
}
func (v *ERABModifyItemBearerModRes) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABModifyItemBearerModRes(v, &s)
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
func (v *ERABModifyItemBearerModRes) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABModifyItemBearerModRes) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABNotToBeModifiedItemBearerModInd) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABNotToBeModifiedItemBearerModInd")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABNotToBeModifiedItemBearerModInd(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABNotToBeModifiedItemBearerModInd")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABNotToBeModifiedItemBearerModInd")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABNotToBeModifiedItemBearerModInd")
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABNotToBeModifiedItemBearerModInd")
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABNotToBeModifiedItemBearerModInd(v, &s)
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
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABNotToBeModifiedItemBearerModInd) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABReleaseItemBearerRelComp) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseItemBearerRelComp")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseItemBearerRelComp")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseItemBearerRelComp(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseItemBearerRelComp")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseItemBearerRelComp")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseItemBearerRelComp")
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseItemBearerRelComp")
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseItemBearerRelComp(v, &s)
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
func (v *ERABReleaseItemBearerRelComp) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseItemBearerRelComp) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABSetupItemBearerSURes) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupItemBearerSURes")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupItemBearerSURes) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupItemBearerSURes")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupItemBearerSURes(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupItemBearerSURes")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupItemBearerSURes")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupItemBearerSURes) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupItemBearerSURes")
}
func (v *ERABSetupItemBearerSURes) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupItemBearerSURes")
}
func (v *ERABSetupItemBearerSURes) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupItemBearerSURes(v, &s)
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
func (v *ERABSetupItemBearerSURes) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupItemBearerSURes) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABSetupItemCtxtSURes) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupItemCtxtSURes")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupItemCtxtSURes) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupItemCtxtSURes")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupItemCtxtSURes(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupItemCtxtSURes")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupItemCtxtSURes")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupItemCtxtSURes) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupItemCtxtSURes")
}
func (v *ERABSetupItemCtxtSURes) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupItemCtxtSURes")
}
func (v *ERABSetupItemCtxtSURes) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupItemCtxtSURes(v, &s)
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
func (v *ERABSetupItemCtxtSURes) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupItemCtxtSURes) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABFailedToSetupItemHOReqAck) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToSetupItemHOReqAck")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedToSetupItemHOReqAck
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedToSetupItemHOReqAck(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedToSetupItemHOReqAck{}
		return report, aper.OperationError(err, "ERABFailedToSetupItemHOReqAck")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedToSetupItemHOReqAck")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyItemBearerModConf) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyItemBearerModConf")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyItemBearerModConf
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyItemBearerModConf(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyItemBearerModConf{}
		return report, aper.OperationError(err, "ERABModifyItemBearerModConf")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyItemBearerModConf")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABModifyItemBearerModRes) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABModifyItemBearerModRes")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABModifyItemBearerModRes
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABModifyItemBearerModRes(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABModifyItemBearerModRes{}
		return report, aper.OperationError(err, "ERABModifyItemBearerModRes")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABModifyItemBearerModRes")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABNotToBeModifiedItemBearerModInd) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABNotToBeModifiedItemBearerModInd")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABNotToBeModifiedItemBearerModInd
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABNotToBeModifiedItemBearerModInd(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABNotToBeModifiedItemBearerModInd{}
		return report, aper.OperationError(err, "ERABNotToBeModifiedItemBearerModInd")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABNotToBeModifiedItemBearerModInd")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABReleaseItemBearerRelComp) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseItemBearerRelComp")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseItemBearerRelComp
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseItemBearerRelComp(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseItemBearerRelComp{}
		return report, aper.OperationError(err, "ERABReleaseItemBearerRelComp")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseItemBearerRelComp")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupItemBearerSURes) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupItemBearerSURes")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupItemBearerSURes
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupItemBearerSURes(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupItemBearerSURes{}
		return report, aper.OperationError(err, "ERABSetupItemBearerSURes")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupItemBearerSURes")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupItemCtxtSURes) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupItemCtxtSURes")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupItemCtxtSURes
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupItemCtxtSURes(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupItemCtxtSURes{}
		return report, aper.OperationError(err, "ERABSetupItemCtxtSURes")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupItemCtxtSURes")
}

type ERABItemIEValue struct {
	id          s00.ProtocolIEID
	received    aper.WireSpan
	replay      aper.Snapshot
	opaque      aper.OpaqueOpenType
	isOpaque    bool
	rowERABItem *ERABItem
}

func (v ERABItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(35):
		return v.rowERABItem != nil
	}
	return false
}
func (v *ERABItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABItemIEs"}}
}
func (ERABItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(35):
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
func (v *ERABItemIEValue) AsERABItem() (*ERABItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(35) || v.rowERABItem == nil {
		return nil, false
	}
	return v.rowERABItem, true
}
func (v ERABItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABItemIEValue, error) {
	out := ERABItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(35):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABItem = &value
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
func (v ERABItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(35):
		if v.rowERABItem == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABItemIEs.id-E-RABItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABItemIEValue:", v.id)
	}
}

type ERABFailedtoSetupItemHOReqAckIEValue struct {
	id                               s00.ProtocolIEID
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           aper.OpaqueOpenType
	isOpaque                         bool
	rowERABFailedtoSetupItemHOReqAck *ERABFailedToSetupItemHOReqAck
}

func (v ERABFailedtoSetupItemHOReqAckIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(21):
		return v.rowERABFailedtoSetupItemHOReqAck != nil
	}
	return false
}
func (v *ERABFailedtoSetupItemHOReqAckIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABFailedtoSetupItemHOReqAckIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedtoSetupItemHOReqAckIEs"}}
}
func (ERABFailedtoSetupItemHOReqAckIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(21):
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
func (v *ERABFailedtoSetupItemHOReqAckIEValue) AsERABFailedtoSetupItemHOReqAck() (*ERABFailedToSetupItemHOReqAck, bool) {
	if v == nil || v.id != s00.ProtocolIEID(21) || v.rowERABFailedtoSetupItemHOReqAck == nil {
		return nil, false
	}
	return v.rowERABFailedtoSetupItemHOReqAck, true
}
func (v ERABFailedtoSetupItemHOReqAckIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABFailedtoSetupItemHOReqAckIEValue, error) {
	out := ERABFailedtoSetupItemHOReqAckIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(21):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABFailedToSetupItemHOReqAck
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedtoSetupItemHOReqAck:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABFailedToSetupItemHOReqAck")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABFailedtoSetupItemHOReqAck = &value
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
func (v ERABFailedtoSetupItemHOReqAckIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABFailedtoSetupItemHOReqAckIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(21):
		if v.rowERABFailedtoSetupItemHOReqAck == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABFailedtoSetupItemHOReqAckIEs.id-E-RABFailedtoSetupItemHOReqAck:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABFailedtoSetupItemHOReqAck.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABFailedtoSetupItemHOReqAckIEValue:", v.id)
	}
}

type ERABModifyItemBearerModConfIEValue struct {
	id                             s00.ProtocolIEID
	received                       aper.WireSpan
	replay                         aper.Snapshot
	opaque                         aper.OpaqueOpenType
	isOpaque                       bool
	rowERABModifyItemBearerModConf *ERABModifyItemBearerModConf
}

func (v ERABModifyItemBearerModConfIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(204):
		return v.rowERABModifyItemBearerModConf != nil
	}
	return false
}
func (v *ERABModifyItemBearerModConfIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModifyItemBearerModConfIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModConfIEs"}}
}
func (ERABModifyItemBearerModConfIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(204):
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
func (v *ERABModifyItemBearerModConfIEValue) AsERABModifyItemBearerModConf() (*ERABModifyItemBearerModConf, bool) {
	if v == nil || v.id != s00.ProtocolIEID(204) || v.rowERABModifyItemBearerModConf == nil {
		return nil, false
	}
	return v.rowERABModifyItemBearerModConf, true
}
func (v ERABModifyItemBearerModConfIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModifyItemBearerModConfIEValue, error) {
	out := ERABModifyItemBearerModConfIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(204):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABModifyItemBearerModConf
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABModifyItemBearerModConf:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModifyItemBearerModConf")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABModifyItemBearerModConf = &value
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
func (v ERABModifyItemBearerModConfIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABModifyItemBearerModConfIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(204):
		if v.rowERABModifyItemBearerModConf == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyItemBearerModConfIEs.id-E-RABModifyItemBearerModConf:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABModifyItemBearerModConf.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModifyItemBearerModConfIEValue:", v.id)
	}
}

type ERABModifyItemBearerModResIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowERABModifyItemBearerModRes *ERABModifyItemBearerModRes
}

func (v ERABModifyItemBearerModResIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(37):
		return v.rowERABModifyItemBearerModRes != nil
	}
	return false
}
func (v *ERABModifyItemBearerModResIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModifyItemBearerModResIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModResIEs"}}
}
func (ERABModifyItemBearerModResIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(37):
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
func (v *ERABModifyItemBearerModResIEValue) AsERABModifyItemBearerModRes() (*ERABModifyItemBearerModRes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(37) || v.rowERABModifyItemBearerModRes == nil {
		return nil, false
	}
	return v.rowERABModifyItemBearerModRes, true
}
func (v ERABModifyItemBearerModResIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModifyItemBearerModResIEValue, error) {
	out := ERABModifyItemBearerModResIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(37):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABModifyItemBearerModRes
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABModifyItemBearerModRes:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModifyItemBearerModRes")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABModifyItemBearerModRes = &value
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
func (v ERABModifyItemBearerModResIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABModifyItemBearerModResIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(37):
		if v.rowERABModifyItemBearerModRes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModifyItemBearerModResIEs.id-E-RABModifyItemBearerModRes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABModifyItemBearerModRes.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModifyItemBearerModResIEValue:", v.id)
	}
}

type ERABNotToBeModifiedItemBearerModIndIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowERABNotToBeModifiedItemBearerModInd *ERABNotToBeModifiedItemBearerModInd
}

func (v ERABNotToBeModifiedItemBearerModIndIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(202):
		return v.rowERABNotToBeModifiedItemBearerModInd != nil
	}
	return false
}
func (v *ERABNotToBeModifiedItemBearerModIndIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABNotToBeModifiedItemBearerModIndIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedItemBearerModIndIEs"}}
}
func (ERABNotToBeModifiedItemBearerModIndIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(202):
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
func (v *ERABNotToBeModifiedItemBearerModIndIEValue) AsERABNotToBeModifiedItemBearerModInd() (*ERABNotToBeModifiedItemBearerModInd, bool) {
	if v == nil || v.id != s00.ProtocolIEID(202) || v.rowERABNotToBeModifiedItemBearerModInd == nil {
		return nil, false
	}
	return v.rowERABNotToBeModifiedItemBearerModInd, true
}
func (v ERABNotToBeModifiedItemBearerModIndIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABNotToBeModifiedItemBearerModIndIEValue, error) {
	out := ERABNotToBeModifiedItemBearerModIndIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(202):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABNotToBeModifiedItemBearerModInd
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABNotToBeModifiedItemBearerModInd:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABNotToBeModifiedItemBearerModInd")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABNotToBeModifiedItemBearerModInd = &value
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
func (v ERABNotToBeModifiedItemBearerModIndIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABNotToBeModifiedItemBearerModIndIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(202):
		if v.rowERABNotToBeModifiedItemBearerModInd == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABNotToBeModifiedItemBearerModIndIEs.id-E-RABNotToBeModifiedItemBearerModInd:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABNotToBeModifiedItemBearerModInd.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABNotToBeModifiedItemBearerModIndIEValue:", v.id)
	}
}

type ERABReleaseItemBearerRelCompIEValue struct {
	id                              s00.ProtocolIEID
	received                        aper.WireSpan
	replay                          aper.Snapshot
	opaque                          aper.OpaqueOpenType
	isOpaque                        bool
	rowERABReleaseItemBearerRelComp *ERABReleaseItemBearerRelComp
}

func (v ERABReleaseItemBearerRelCompIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(15):
		return v.rowERABReleaseItemBearerRelComp != nil
	}
	return false
}
func (v *ERABReleaseItemBearerRelCompIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABReleaseItemBearerRelCompIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseItemBearerRelCompIEs"}}
}
func (ERABReleaseItemBearerRelCompIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(15):
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
func (v *ERABReleaseItemBearerRelCompIEValue) AsERABReleaseItemBearerRelComp() (*ERABReleaseItemBearerRelComp, bool) {
	if v == nil || v.id != s00.ProtocolIEID(15) || v.rowERABReleaseItemBearerRelComp == nil {
		return nil, false
	}
	return v.rowERABReleaseItemBearerRelComp, true
}
func (v ERABReleaseItemBearerRelCompIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABReleaseItemBearerRelCompIEValue, error) {
	out := ERABReleaseItemBearerRelCompIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(15):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABReleaseItemBearerRelComp
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABReleaseItemBearerRelComp:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABReleaseItemBearerRelComp")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABReleaseItemBearerRelComp = &value
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
func (v ERABReleaseItemBearerRelCompIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABReleaseItemBearerRelCompIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(15):
		if v.rowERABReleaseItemBearerRelComp == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABReleaseItemBearerRelCompIEs.id-E-RABReleaseItemBearerRelComp:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABReleaseItemBearerRelComp.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABReleaseItemBearerRelCompIEValue:", v.id)
	}
}

type ERABSetupItemBearerSUResIEValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowERABSetupItemBearerSURes *ERABSetupItemBearerSURes
}

func (v ERABSetupItemBearerSUResIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(39):
		return v.rowERABSetupItemBearerSURes != nil
	}
	return false
}
func (v *ERABSetupItemBearerSUResIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABSetupItemBearerSUResIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemBearerSUResIEs"}}
}
func (ERABSetupItemBearerSUResIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(39):
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
func (v *ERABSetupItemBearerSUResIEValue) AsERABSetupItemBearerSURes() (*ERABSetupItemBearerSURes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(39) || v.rowERABSetupItemBearerSURes == nil {
		return nil, false
	}
	return v.rowERABSetupItemBearerSURes, true
}
func (v ERABSetupItemBearerSUResIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABSetupItemBearerSUResIEValue, error) {
	out := ERABSetupItemBearerSUResIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(39):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABSetupItemBearerSURes
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABSetupItemBearerSURes:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupItemBearerSURes")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABSetupItemBearerSURes = &value
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
func (v ERABSetupItemBearerSUResIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABSetupItemBearerSUResIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(39):
		if v.rowERABSetupItemBearerSURes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupItemBearerSUResIEs.id-E-RABSetupItemBearerSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABSetupItemBearerSURes.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABSetupItemBearerSUResIEValue:", v.id)
	}
}

type ERABSetupItemCtxtSUResIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowERABSetupItemCtxtSURes *ERABSetupItemCtxtSURes
}

func (v ERABSetupItemCtxtSUResIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(50):
		return v.rowERABSetupItemCtxtSURes != nil
	}
	return false
}
func (v *ERABSetupItemCtxtSUResIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABSetupItemCtxtSUResIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSUResIEs"}}
}
func (ERABSetupItemCtxtSUResIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(50):
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
func (v *ERABSetupItemCtxtSUResIEValue) AsERABSetupItemCtxtSURes() (*ERABSetupItemCtxtSURes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(50) || v.rowERABSetupItemCtxtSURes == nil {
		return nil, false
	}
	return v.rowERABSetupItemCtxtSURes, true
}
func (v ERABSetupItemCtxtSUResIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABSetupItemCtxtSUResIEValue, error) {
	out := ERABSetupItemCtxtSUResIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(50):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ERABSetupItemCtxtSURes
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ERABSetupItemCtxtSURes:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupItemCtxtSURes")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowERABSetupItemCtxtSURes = &value
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
func (v ERABSetupItemCtxtSUResIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ERABSetupItemCtxtSUResIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(50):
		if v.rowERABSetupItemCtxtSURes == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABSetupItemCtxtSUResIEs.id-E-RABSetupItemCtxtSURes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowERABSetupItemCtxtSURes.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABSetupItemCtxtSUResIEValue:", v.id)
	}
}

type ERABItemIETable struct{}

func ERABItemIEs() ERABItemIETable { return ERABItemIETable{} }
func (ERABItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABItemIEs"}
		return sealed
	}()
}
func (ERABItemIETable) Table() s00.ERABItemIEValueIETable {
	return func() s00.ERABItemIEValueIETable {
		sealed := s00.ERABItemIEValueIETable{}
		*s00.BridgeERABItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABItemIETable) infoERABItem() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABItemIEs().ID(), ID: s00.ProtocolIEID(35), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABItemIEs", Row: "id-E-RABItem"}}}
}
func (t ERABItemIETable) ERABItem() ERABItemERABItemIEBinding {
	return ERABItemERABItemIEBinding{info: t.infoERABItem(), codec: ERABItemValueCodec{path: "ERABItem",
		decode: func(data []byte, options aper.DecodeState) (ERABItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABItem
				return empty, err
			}
			var zero ERABItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(35), raw)
			if err != nil {
				var empty ERABItem
				return empty, err
			}
			value, ok := decoded.AsERABItem()
			if !ok {
				var empty ERABItem
				return empty, fmt.Errorf("binding E-RABItemIEs.id-E-RABItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABItemIEValue{id: s00.ProtocolIEID(35), rowERABItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABItem, options aper.DecodeState) (ERABItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			BridgeCaptureS1APERABItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABItem) ERABItemIEValue {
		return ERABItemIEValue{id: s00.ProtocolIEID(35), rowERABItem: &value}
	}, get: func(value *ERABItemIEValue) (*ERABItem, bool) { return value.AsERABItem() }}
}
func (t ERABItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(35):
		return ERABItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABItemIEField{Id: id, Criticality: criticality, Value: ERABItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABFailedtoSetupItemHOReqAckIETable struct{}

func ERABFailedtoSetupItemHOReqAckIEs() ERABFailedtoSetupItemHOReqAckIETable {
	return ERABFailedtoSetupItemHOReqAckIETable{}
}
func (ERABFailedtoSetupItemHOReqAckIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedtoSetupItemHOReqAckIEs"}
		return sealed
	}()
}
func (ERABFailedtoSetupItemHOReqAckIETable) Table() s00.ERABFailedtoSetupItemHOReqAckIEValueIETable {
	return func() s00.ERABFailedtoSetupItemHOReqAckIEValueIETable {
		sealed := s00.ERABFailedtoSetupItemHOReqAckIEValueIETable{}
		*s00.BridgeERABFailedtoSetupItemHOReqAckIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABFailedtoSetupItemHOReqAckIETable) infoERABFailedtoSetupItemHOReqAck() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABFailedtoSetupItemHOReqAckIEs().ID(), ID: s00.ProtocolIEID(21), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToSetupItemHOReqAck"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedtoSetupItemHOReqAckIEs", Row: "id-E-RABFailedtoSetupItemHOReqAck"}}}
}
func (t ERABFailedtoSetupItemHOReqAckIETable) ERABFailedtoSetupItemHOReqAck() ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding {
	return ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding{info: t.infoERABFailedtoSetupItemHOReqAck(), codec: ERABFailedToSetupItemHOReqAckValueCodec{path: "ERABFailedToSetupItemHOReqAck",
		decode: func(data []byte, options aper.DecodeState) (ERABFailedToSetupItemHOReqAck, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABFailedToSetupItemHOReqAck
				return empty, err
			}
			var zero ERABFailedtoSetupItemHOReqAckIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(21), raw)
			if err != nil {
				var empty ERABFailedToSetupItemHOReqAck
				return empty, err
			}
			value, ok := decoded.AsERABFailedtoSetupItemHOReqAck()
			if !ok {
				var empty ERABFailedToSetupItemHOReqAck
				return empty, fmt.Errorf("binding E-RABFailedtoSetupItemHOReqAckIEs.id-E-RABFailedtoSetupItemHOReqAck: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABFailedToSetupItemHOReqAck, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABFailedtoSetupItemHOReqAckIEValue{id: s00.ProtocolIEID(21), rowERABFailedtoSetupItemHOReqAck: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABFailedToSetupItemHOReqAck, options aper.DecodeState) (ERABFailedToSetupItemHOReqAck, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABFailedToSetupItemHOReqAck(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABFailedToSetupItemHOReqAck, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APERABFailedToSetupItemHOReqAck(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABFailedToSetupItemHOReqAck"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABFailedToSetupItemHOReqAck) ERABFailedtoSetupItemHOReqAckIEValue {
		return ERABFailedtoSetupItemHOReqAckIEValue{id: s00.ProtocolIEID(21), rowERABFailedtoSetupItemHOReqAck: &value}
	}, get: func(value *ERABFailedtoSetupItemHOReqAckIEValue) (*ERABFailedToSetupItemHOReqAck, bool) {
		return value.AsERABFailedtoSetupItemHOReqAck()
	}}
}
func (t ERABFailedtoSetupItemHOReqAckIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABFailedtoSetupItemHOReqAckIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(21):
		return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedtoSetupItemHOReqAck requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABFailedtoSetupItemHOReqAckIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABFailedtoSetupItemHOReqAckIEField{Id: id, Criticality: criticality, Value: ERABFailedtoSetupItemHOReqAckIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyItemBearerModConfIETable struct{}

func ERABModifyItemBearerModConfIEs() ERABModifyItemBearerModConfIETable {
	return ERABModifyItemBearerModConfIETable{}
}
func (ERABModifyItemBearerModConfIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModConfIEs"}
		return sealed
	}()
}
func (ERABModifyItemBearerModConfIETable) Table() s00.ERABModifyItemBearerModConfIEValueIETable {
	return func() s00.ERABModifyItemBearerModConfIEValueIETable {
		sealed := s00.ERABModifyItemBearerModConfIEValueIETable{}
		*s00.BridgeERABModifyItemBearerModConfIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModifyItemBearerModConfIETable) infoERABModifyItemBearerModConf() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyItemBearerModConfIEs().ID(), ID: s00.ProtocolIEID(204), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModConf"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModConfIEs", Row: "id-E-RABModifyItemBearerModConf"}}}
}
func (t ERABModifyItemBearerModConfIETable) ERABModifyItemBearerModConf() ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding {
	return ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding{info: t.infoERABModifyItemBearerModConf(), codec: ERABModifyItemBearerModConfValueCodec{path: "ERABModifyItemBearerModConf",
		decode: func(data []byte, options aper.DecodeState) (ERABModifyItemBearerModConf, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABModifyItemBearerModConf
				return empty, err
			}
			var zero ERABModifyItemBearerModConfIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(204), raw)
			if err != nil {
				var empty ERABModifyItemBearerModConf
				return empty, err
			}
			value, ok := decoded.AsERABModifyItemBearerModConf()
			if !ok {
				var empty ERABModifyItemBearerModConf
				return empty, fmt.Errorf("binding E-RABModifyItemBearerModConfIEs.id-E-RABModifyItemBearerModConf: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABModifyItemBearerModConf, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyItemBearerModConfIEValue{id: s00.ProtocolIEID(204), rowERABModifyItemBearerModConf: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABModifyItemBearerModConf, options aper.DecodeState) (ERABModifyItemBearerModConf, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABModifyItemBearerModConf(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v ERABModifyItemBearerModConf, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APERABModifyItemBearerModConf(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyItemBearerModConf"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABModifyItemBearerModConf) ERABModifyItemBearerModConfIEValue {
		return ERABModifyItemBearerModConfIEValue{id: s00.ProtocolIEID(204), rowERABModifyItemBearerModConf: &value}
	}, get: func(value *ERABModifyItemBearerModConfIEValue) (*ERABModifyItemBearerModConf, bool) {
		return value.AsERABModifyItemBearerModConf()
	}}
}
func (t ERABModifyItemBearerModConfIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABModifyItemBearerModConfIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(204):
		return ERABModifyItemBearerModConfIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABModifyItemBearerModConf requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyItemBearerModConfIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyItemBearerModConfIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyItemBearerModConfIEField{Id: id, Criticality: criticality, Value: ERABModifyItemBearerModConfIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABModifyItemBearerModResIETable struct{}

func ERABModifyItemBearerModResIEs() ERABModifyItemBearerModResIETable {
	return ERABModifyItemBearerModResIETable{}
}
func (ERABModifyItemBearerModResIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModResIEs"}
		return sealed
	}()
}
func (ERABModifyItemBearerModResIETable) Table() s00.ERABModifyItemBearerModResIEValueIETable {
	return func() s00.ERABModifyItemBearerModResIEValueIETable {
		sealed := s00.ERABModifyItemBearerModResIEValueIETable{}
		*s00.BridgeERABModifyItemBearerModResIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABModifyItemBearerModResIETable) infoERABModifyItemBearerModRes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABModifyItemBearerModResIEs().ID(), ID: s00.ProtocolIEID(37), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModRes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModifyItemBearerModResIEs", Row: "id-E-RABModifyItemBearerModRes"}}}
}
func (t ERABModifyItemBearerModResIETable) ERABModifyItemBearerModRes() ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding {
	return ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding{info: t.infoERABModifyItemBearerModRes(), codec: ERABModifyItemBearerModResValueCodec{path: "ERABModifyItemBearerModRes",
		decode: func(data []byte, options aper.DecodeState) (ERABModifyItemBearerModRes, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABModifyItemBearerModRes
				return empty, err
			}
			var zero ERABModifyItemBearerModResIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(37), raw)
			if err != nil {
				var empty ERABModifyItemBearerModRes
				return empty, err
			}
			value, ok := decoded.AsERABModifyItemBearerModRes()
			if !ok {
				var empty ERABModifyItemBearerModRes
				return empty, fmt.Errorf("binding E-RABModifyItemBearerModResIEs.id-E-RABModifyItemBearerModRes: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABModifyItemBearerModRes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABModifyItemBearerModResIEValue{id: s00.ProtocolIEID(37), rowERABModifyItemBearerModRes: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABModifyItemBearerModRes, options aper.DecodeState) (ERABModifyItemBearerModRes, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABModifyItemBearerModRes(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}, compare: func(v ERABModifyItemBearerModRes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABModifyItemBearerModRes(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABModifyItemBearerModRes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABModifyItemBearerModRes) ERABModifyItemBearerModResIEValue {
		return ERABModifyItemBearerModResIEValue{id: s00.ProtocolIEID(37), rowERABModifyItemBearerModRes: &value}
	}, get: func(value *ERABModifyItemBearerModResIEValue) (*ERABModifyItemBearerModRes, bool) {
		return value.AsERABModifyItemBearerModRes()
	}}
}
func (t ERABModifyItemBearerModResIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABModifyItemBearerModResIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(37):
		return ERABModifyItemBearerModResIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABModifyItemBearerModRes requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABModifyItemBearerModResIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABModifyItemBearerModResIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABModifyItemBearerModResIEField{Id: id, Criticality: criticality, Value: ERABModifyItemBearerModResIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABNotToBeModifiedItemBearerModIndIETable struct{}

func ERABNotToBeModifiedItemBearerModIndIEs() ERABNotToBeModifiedItemBearerModIndIETable {
	return ERABNotToBeModifiedItemBearerModIndIETable{}
}
func (ERABNotToBeModifiedItemBearerModIndIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedItemBearerModIndIEs"}
		return sealed
	}()
}
func (ERABNotToBeModifiedItemBearerModIndIETable) Table() s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable {
	return func() s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable {
		sealed := s00.ERABNotToBeModifiedItemBearerModIndIEValueIETable{}
		*s00.BridgeERABNotToBeModifiedItemBearerModIndIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABNotToBeModifiedItemBearerModIndIETable) infoERABNotToBeModifiedItemBearerModInd() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABNotToBeModifiedItemBearerModIndIEs().ID(), ID: s00.ProtocolIEID(202), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedItemBearerModInd"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABNotToBeModifiedItemBearerModIndIEs", Row: "id-E-RABNotToBeModifiedItemBearerModInd"}}}
}
func (t ERABNotToBeModifiedItemBearerModIndIETable) ERABNotToBeModifiedItemBearerModInd() ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding {
	return ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding{info: t.infoERABNotToBeModifiedItemBearerModInd(), codec: ERABNotToBeModifiedItemBearerModIndValueCodec{path: "ERABNotToBeModifiedItemBearerModInd",
		decode: func(data []byte, options aper.DecodeState) (ERABNotToBeModifiedItemBearerModInd, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABNotToBeModifiedItemBearerModInd
				return empty, err
			}
			var zero ERABNotToBeModifiedItemBearerModIndIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(202), raw)
			if err != nil {
				var empty ERABNotToBeModifiedItemBearerModInd
				return empty, err
			}
			value, ok := decoded.AsERABNotToBeModifiedItemBearerModInd()
			if !ok {
				var empty ERABNotToBeModifiedItemBearerModInd
				return empty, fmt.Errorf("binding E-RABNotToBeModifiedItemBearerModIndIEs.id-E-RABNotToBeModifiedItemBearerModInd: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABNotToBeModifiedItemBearerModInd, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABNotToBeModifiedItemBearerModIndIEValue{id: s00.ProtocolIEID(202), rowERABNotToBeModifiedItemBearerModInd: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABNotToBeModifiedItemBearerModInd, options aper.DecodeState) (ERABNotToBeModifiedItemBearerModInd, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABNotToBeModifiedItemBearerModInd(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}, compare: func(v ERABNotToBeModifiedItemBearerModInd, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABNotToBeModifiedItemBearerModInd(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABNotToBeModifiedItemBearerModInd"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABNotToBeModifiedItemBearerModInd) ERABNotToBeModifiedItemBearerModIndIEValue {
		return ERABNotToBeModifiedItemBearerModIndIEValue{id: s00.ProtocolIEID(202), rowERABNotToBeModifiedItemBearerModInd: &value}
	}, get: func(value *ERABNotToBeModifiedItemBearerModIndIEValue) (*ERABNotToBeModifiedItemBearerModInd, bool) {
		return value.AsERABNotToBeModifiedItemBearerModInd()
	}}
}
func (t ERABNotToBeModifiedItemBearerModIndIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABNotToBeModifiedItemBearerModIndIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(202):
		return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABNotToBeModifiedItemBearerModInd requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABNotToBeModifiedItemBearerModIndIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABNotToBeModifiedItemBearerModIndIEField{Id: id, Criticality: criticality, Value: ERABNotToBeModifiedItemBearerModIndIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABReleaseItemBearerRelCompIETable struct{}

func ERABReleaseItemBearerRelCompIEs() ERABReleaseItemBearerRelCompIETable {
	return ERABReleaseItemBearerRelCompIETable{}
}
func (ERABReleaseItemBearerRelCompIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseItemBearerRelCompIEs"}
		return sealed
	}()
}
func (ERABReleaseItemBearerRelCompIETable) Table() s00.ERABReleaseItemBearerRelCompIEValueIETable {
	return func() s00.ERABReleaseItemBearerRelCompIEValueIETable {
		sealed := s00.ERABReleaseItemBearerRelCompIEValueIETable{}
		*s00.BridgeERABReleaseItemBearerRelCompIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABReleaseItemBearerRelCompIETable) infoERABReleaseItemBearerRelComp() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABReleaseItemBearerRelCompIEs().ID(), ID: s00.ProtocolIEID(15), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseItemBearerRelComp"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABReleaseItemBearerRelCompIEs", Row: "id-E-RABReleaseItemBearerRelComp"}}}
}
func (t ERABReleaseItemBearerRelCompIETable) ERABReleaseItemBearerRelComp() ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding {
	return ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding{info: t.infoERABReleaseItemBearerRelComp(), codec: ERABReleaseItemBearerRelCompValueCodec{path: "ERABReleaseItemBearerRelComp",
		decode: func(data []byte, options aper.DecodeState) (ERABReleaseItemBearerRelComp, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABReleaseItemBearerRelComp
				return empty, err
			}
			var zero ERABReleaseItemBearerRelCompIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(15), raw)
			if err != nil {
				var empty ERABReleaseItemBearerRelComp
				return empty, err
			}
			value, ok := decoded.AsERABReleaseItemBearerRelComp()
			if !ok {
				var empty ERABReleaseItemBearerRelComp
				return empty, fmt.Errorf("binding E-RABReleaseItemBearerRelCompIEs.id-E-RABReleaseItemBearerRelComp: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABReleaseItemBearerRelComp, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABReleaseItemBearerRelCompIEValue{id: s00.ProtocolIEID(15), rowERABReleaseItemBearerRelComp: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABReleaseItemBearerRelComp, options aper.DecodeState) (ERABReleaseItemBearerRelComp, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABReleaseItemBearerRelComp(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABReleaseItemBearerRelComp, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APERABReleaseItemBearerRelComp(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABReleaseItemBearerRelComp"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABReleaseItemBearerRelComp) ERABReleaseItemBearerRelCompIEValue {
		return ERABReleaseItemBearerRelCompIEValue{id: s00.ProtocolIEID(15), rowERABReleaseItemBearerRelComp: &value}
	}, get: func(value *ERABReleaseItemBearerRelCompIEValue) (*ERABReleaseItemBearerRelComp, bool) {
		return value.AsERABReleaseItemBearerRelComp()
	}}
}
func (t ERABReleaseItemBearerRelCompIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABReleaseItemBearerRelCompIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(15):
		return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABReleaseItemBearerRelComp requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABReleaseItemBearerRelCompIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABReleaseItemBearerRelCompIEField{Id: id, Criticality: criticality, Value: ERABReleaseItemBearerRelCompIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupItemBearerSUResIETable struct{}

func ERABSetupItemBearerSUResIEs() ERABSetupItemBearerSUResIETable {
	return ERABSetupItemBearerSUResIETable{}
}
func (ERABSetupItemBearerSUResIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemBearerSUResIEs"}
		return sealed
	}()
}
func (ERABSetupItemBearerSUResIETable) Table() s00.ERABSetupItemBearerSUResIEValueIETable {
	return func() s00.ERABSetupItemBearerSUResIEValueIETable {
		sealed := s00.ERABSetupItemBearerSUResIEValueIETable{}
		*s00.BridgeERABSetupItemBearerSUResIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ERABSetupItemBearerSUResIETable) infoERABSetupItemBearerSURes() s00.FieldInfo {
	return s00.FieldInfo{Table: ERABSetupItemBearerSUResIEs().ID(), ID: s00.ProtocolIEID(39), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemBearerSURes"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemBearerSUResIEs", Row: "id-E-RABSetupItemBearerSURes"}}}
}
func (t ERABSetupItemBearerSUResIETable) ERABSetupItemBearerSURes() ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding {
	return ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding{info: t.infoERABSetupItemBearerSURes(), codec: ERABSetupItemBearerSUResValueCodec{path: "ERABSetupItemBearerSURes",
		decode: func(data []byte, options aper.DecodeState) (ERABSetupItemBearerSURes, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABSetupItemBearerSURes
				return empty, err
			}
			var zero ERABSetupItemBearerSUResIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(39), raw)
			if err != nil {
				var empty ERABSetupItemBearerSURes
				return empty, err
			}
			value, ok := decoded.AsERABSetupItemBearerSURes()
			if !ok {
				var empty ERABSetupItemBearerSURes
				return empty, fmt.Errorf("binding E-RABSetupItemBearerSUResIEs.id-E-RABSetupItemBearerSURes: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABSetupItemBearerSURes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupItemBearerSUResIEValue{id: s00.ProtocolIEID(39), rowERABSetupItemBearerSURes: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABSetupItemBearerSURes, options aper.DecodeState) (ERABSetupItemBearerSURes, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABSetupItemBearerSURes(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ERABSetupItemBearerSURes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABSetupItemBearerSURes(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupItemBearerSURes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABSetupItemBearerSURes) ERABSetupItemBearerSUResIEValue {
		return ERABSetupItemBearerSUResIEValue{id: s00.ProtocolIEID(39), rowERABSetupItemBearerSURes: &value}
	}, get: func(value *ERABSetupItemBearerSUResIEValue) (*ERABSetupItemBearerSURes, bool) {
		return value.AsERABSetupItemBearerSURes()
	}}
}
func (t ERABSetupItemBearerSUResIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABSetupItemBearerSUResIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(39):
		return ERABSetupItemBearerSUResIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSetupItemBearerSURes requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupItemBearerSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupItemBearerSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupItemBearerSUResIEField{Id: id, Criticality: criticality, Value: ERABSetupItemBearerSUResIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ERABSetupItemCtxtSUResIETable struct{}

func ERABSetupItemCtxtSUResIEs() ERABSetupItemCtxtSUResIETable {
	return ERABSetupItemCtxtSUResIETable{}
}
func (ERABSetupItemCtxtSUResIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABSetupItemCtxtSUResIEs"}
		return sealed
	}()
}
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
func (t ERABSetupItemCtxtSUResIETable) ERABSetupItemCtxtSURes() ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding {
	return ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding{info: t.infoERABSetupItemCtxtSURes(), codec: ERABSetupItemCtxtSUResValueCodec{path: "ERABSetupItemCtxtSURes",
		decode: func(data []byte, options aper.DecodeState) (ERABSetupItemCtxtSURes, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ERABSetupItemCtxtSURes
				return empty, err
			}
			var zero ERABSetupItemCtxtSUResIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(50), raw)
			if err != nil {
				var empty ERABSetupItemCtxtSURes
				return empty, err
			}
			value, ok := decoded.AsERABSetupItemCtxtSURes()
			if !ok {
				var empty ERABSetupItemCtxtSURes
				return empty, fmt.Errorf("binding E-RABSetupItemCtxtSUResIEs.id-E-RABSetupItemCtxtSURes: no selected value")
			}
			return *value, nil
		},
		encode: func(value ERABSetupItemCtxtSURes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ERABSetupItemCtxtSUResIEValue{id: s00.ProtocolIEID(50), rowERABSetupItemCtxtSURes: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ERABSetupItemCtxtSURes, options aper.DecodeState) (ERABSetupItemCtxtSURes, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APERABSetupItemCtxtSURes(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ERABSetupItemCtxtSURes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABSetupItemCtxtSURes(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABSetupItemCtxtSURes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ERABSetupItemCtxtSURes) ERABSetupItemCtxtSUResIEValue {
		return ERABSetupItemCtxtSUResIEValue{id: s00.ProtocolIEID(50), rowERABSetupItemCtxtSURes: &value}
	}, get: func(value *ERABSetupItemCtxtSUResIEValue) (*ERABSetupItemCtxtSURes, bool) {
		return value.AsERABSetupItemCtxtSURes()
	}}
}
func (t ERABSetupItemCtxtSUResIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ERABSetupItemCtxtSUResIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(50):
		return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABSetupItemCtxtSURes requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ERABSetupItemCtxtSUResIEField{}, aper.OperationError(err, "Opaque")
		}
		return ERABSetupItemCtxtSUResIEField{Id: id, Criticality: criticality, Value: ERABSetupItemCtxtSUResIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ERABFailedToSetupItemHOReqAckCodec binds the complete APER value type.
func ERABFailedToSetupItemHOReqAckCodec() ERABFailedToSetupItemHOReqAckValueCodec {
	return ERABFailedtoSetupItemHOReqAckIEs().ERABFailedtoSetupItemHOReqAck().Codec()
}

// ERABItemCodec binds the complete APER value type.
func ERABItemCodec() ERABItemValueCodec { return ERABItemIEs().ERABItem().Codec() }

// ERABModifyItemBearerModConfCodec binds the complete APER value type.
func ERABModifyItemBearerModConfCodec() ERABModifyItemBearerModConfValueCodec {
	return ERABModifyItemBearerModConfIEs().ERABModifyItemBearerModConf().Codec()
}

// ERABModifyItemBearerModResCodec binds the complete APER value type.
func ERABModifyItemBearerModResCodec() ERABModifyItemBearerModResValueCodec {
	return ERABModifyItemBearerModResIEs().ERABModifyItemBearerModRes().Codec()
}

// ERABNotToBeModifiedItemBearerModIndCodec binds the complete APER value type.
func ERABNotToBeModifiedItemBearerModIndCodec() ERABNotToBeModifiedItemBearerModIndValueCodec {
	return ERABNotToBeModifiedItemBearerModIndIEs().ERABNotToBeModifiedItemBearerModInd().Codec()
}

// ERABReleaseItemBearerRelCompCodec binds the complete APER value type.
func ERABReleaseItemBearerRelCompCodec() ERABReleaseItemBearerRelCompValueCodec {
	return ERABReleaseItemBearerRelCompIEs().ERABReleaseItemBearerRelComp().Codec()
}

// ERABSetupItemBearerSUResCodec binds the complete APER value type.
func ERABSetupItemBearerSUResCodec() ERABSetupItemBearerSUResValueCodec {
	return ERABSetupItemBearerSUResIEs().ERABSetupItemBearerSURes().Codec()
}

// ERABSetupItemCtxtSUResCodec binds the complete APER value type.
func ERABSetupItemCtxtSUResCodec() ERABSetupItemCtxtSUResValueCodec {
	return ERABSetupItemCtxtSUResIEs().ERABSetupItemCtxtSURes().Codec()
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldCapture(v *ERABFailedToResumeListResumeResValueCodec) *func(s15.ERABFailedToResumeListResumeRes, aper.DecodeState) (s15.ERABFailedToResumeListResumeRes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldCompare(v *ERABFailedToResumeListResumeResValueCodec) *func(s15.ERABFailedToResumeListResumeRes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldContext(v *ERABFailedToResumeListResumeResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldDecode(v *ERABFailedToResumeListResumeResValueCodec) *func([]byte, aper.DecodeState) (s15.ERABFailedToResumeListResumeRes, error) {
	return &v.decode
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldEncode(v *ERABFailedToResumeListResumeResValueCodec) *func(s15.ERABFailedToResumeListResumeRes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToResumeListResumeResValueCodecFieldPath(v *ERABFailedToResumeListResumeResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToResumeListResumeResValueCodecMethodEncodeBudgetValue(v ERABFailedToResumeListResumeResValueCodec, a0 s15.ERABFailedToResumeListResumeRes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToResumeListResumeResValueCodecMethodEncodeChanged(v ERABFailedToResumeListResumeResValueCodec, a0 s15.ERABFailedToResumeListResumeRes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedToSetupItemHOReqAckAPERValueFieldContext(v *ERABFailedToSetupItemHOReqAckAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToSetupItemHOReqAckAPERValueFieldReceived(v *ERABFailedToSetupItemHOReqAckAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedToSetupItemHOReqAckAPERValueFieldReplay(v *ERABFailedToSetupItemHOReqAckAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToSetupItemHOReqAckAPERValueFieldWithoutReplay(v *ERABFailedToSetupItemHOReqAckAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToSetupItemHOReqAckFieldExtCount(v *ERABFailedToSetupItemHOReqAck) *int64 {
	return &v.extCount
}
func BridgeERABFailedToSetupItemHOReqAckFieldExtData(v *ERABFailedToSetupItemHOReqAck) *[][]byte {
	return &v.extData
}
func BridgeERABFailedToSetupItemHOReqAckFieldExtOrigin(v *ERABFailedToSetupItemHOReqAck) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABFailedToSetupItemHOReqAckFieldExtPresent(v *ERABFailedToSetupItemHOReqAck) *[]bool {
	return &v.extPresent
}
func BridgeERABFailedToSetupItemHOReqAckFieldExtWire(v *ERABFailedToSetupItemHOReqAck) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABFailedToSetupItemHOReqAckFieldIEExtensionsIndef(v *ERABFailedToSetupItemHOReqAck) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABFailedToSetupItemHOReqAckFieldPerExtPadding(v *ERABFailedToSetupItemHOReqAck) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABFailedToSetupItemHOReqAckFieldPerPadding(v *ERABFailedToSetupItemHOReqAck) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABFailedToSetupItemHOReqAckFieldReceived(v *ERABFailedToSetupItemHOReqAck) *bool {
	return &v.received
}
func BridgeERABFailedToSetupItemHOReqAckFieldReceivedAbsolute(v *ERABFailedToSetupItemHOReqAck) *bool {
	return &v.receivedAbsolute
}
func BridgeERABFailedToSetupItemHOReqAckFieldReceivedBytes(v *ERABFailedToSetupItemHOReqAck) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABFailedToSetupItemHOReqAckFieldReceivedLocation(v *ERABFailedToSetupItemHOReqAck) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABFailedToSetupItemHOReqAckFieldReplay(v *ERABFailedToSetupItemHOReqAck) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedToSetupItemHOReqAckFieldStream(v *ERABFailedToSetupItemHOReqAck) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedToSetupItemHOReqAckFieldWithoutReplay(v *ERABFailedToSetupItemHOReqAck) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERBudget(v *ERABFailedToSetupItemHOReqAck, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERBudgetValue(v *ERABFailedToSetupItemHOReqAck, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERChanged(v *ERABFailedToSetupItemHOReqAck, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERChangedValue(v *ERABFailedToSetupItemHOReqAck, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERLegacy(v *ERABFailedToSetupItemHOReqAck) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERNewValue(v *ERABFailedToSetupItemHOReqAck, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERPlanned(v *ERABFailedToSetupItemHOReqAck, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABFailedToSetupItemHOReqAckMethodMarshalAPERTo(v *ERABFailedToSetupItemHOReqAck, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedToSetupItemHOReqAckMethodUnmarshalAPERFrom(v *ERABFailedToSetupItemHOReqAck, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedToSetupItemHOReqAckMethodUnmarshalAPERLegacy(v *ERABFailedToSetupItemHOReqAck, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABFailedToSetupItemHOReqAckMethodUnmarshalAPERWithOptions(v *ERABFailedToSetupItemHOReqAck, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldCapture(v *ERABFailedToSetupItemHOReqAckValueCodec) *func(ERABFailedToSetupItemHOReqAck, aper.DecodeState) (ERABFailedToSetupItemHOReqAck, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldCompare(v *ERABFailedToSetupItemHOReqAckValueCodec) *func(ERABFailedToSetupItemHOReqAck, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldContext(v *ERABFailedToSetupItemHOReqAckValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldDecode(v *ERABFailedToSetupItemHOReqAckValueCodec) *func([]byte, aper.DecodeState) (ERABFailedToSetupItemHOReqAck, error) {
	return &v.decode
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldEncode(v *ERABFailedToSetupItemHOReqAckValueCodec) *func(ERABFailedToSetupItemHOReqAck, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecFieldPath(v *ERABFailedToSetupItemHOReqAckValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecMethodEncodeBudgetValue(v ERABFailedToSetupItemHOReqAckValueCodec, a0 ERABFailedToSetupItemHOReqAck, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedToSetupItemHOReqAckValueCodecMethodEncodeChanged(v ERABFailedToSetupItemHOReqAckValueCodec, a0 ERABFailedToSetupItemHOReqAck, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBindingFieldCodec(v *ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) *ERABFailedToSetupItemHOReqAckValueCodec {
	return &v.codec
}
func BridgeERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBindingFieldGet(v *ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) *func(*ERABFailedtoSetupItemHOReqAckIEValue) (*ERABFailedToSetupItemHOReqAck, bool) {
	return &v.get
}
func BridgeERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBindingFieldInfo(v *ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBindingFieldInject(v *ERABFailedtoSetupItemHOReqAckERABFailedToSetupItemHOReqAckIEBinding) *func(ERABFailedToSetupItemHOReqAck) ERABFailedtoSetupItemHOReqAckIEValue {
	return &v.inject
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerAPERValueFieldContext(v *ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerAPERValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerAPERValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerAPERValueFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCapture(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEContainer, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldCompare(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldContext(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldDecode(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEContainer, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldEncode(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecFieldPath(v *ERABFailedtoSetupItemHOReqAckIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupItemHOReqAckIEContainerValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupItemHOReqAckIEContainerValueCodecMethodEncodeChanged(v ERABFailedtoSetupItemHOReqAckIEContainerValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldAPERValueFieldContext(v *ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldAPERValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldAPERValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldAPERValueFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldStream(v *ERABFailedtoSetupItemHOReqAckIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodMarshalAPERTo(v *ERABFailedtoSetupItemHOReqAckIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldMethodUnmarshalAPERFrom(v *ERABFailedtoSetupItemHOReqAckIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCapture(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEField, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldCompare(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldContext(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldDecode(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEField, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldEncode(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecFieldPath(v *ERABFailedtoSetupItemHOReqAckIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupItemHOReqAckIEFieldValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupItemHOReqAckIEFieldValueCodecMethodEncodeChanged(v ERABFailedtoSetupItemHOReqAckIEFieldValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupItemHOReqAckIETableMethodInfoERABFailedtoSetupItemHOReqAck(v ERABFailedtoSetupItemHOReqAckIETable) s00.FieldInfo {
	return v.infoERABFailedtoSetupItemHOReqAck()
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValueFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCapture(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldCompare(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldDecode(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldEncode(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecFieldPath(v *ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldId(v *ERABFailedtoSetupItemHOReqAckIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldIsOpaque(v *ERABFailedtoSetupItemHOReqAckIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldOpaque(v *ERABFailedtoSetupItemHOReqAckIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueFieldRowERABFailedtoSetupItemHOReqAck(v *ERABFailedtoSetupItemHOReqAckIEValue) **ERABFailedToSetupItemHOReqAck {
	return &v.rowERABFailedtoSetupItemHOReqAck
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCaptureSemantics(v ERABFailedtoSetupItemHOReqAckIEValue, a0 aper.SemanticCapture) ERABFailedtoSetupItemHOReqAckIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodCompareSemantics(v ERABFailedtoSetupItemHOReqAckIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodDecode(v ERABFailedtoSetupItemHOReqAckIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABFailedtoSetupItemHOReqAckIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodEncode(v ERABFailedtoSetupItemHOReqAckIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodEncodeFresh(v ERABFailedtoSetupItemHOReqAckIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodMatchesID(v ERABFailedtoSetupItemHOReqAckIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodReason(v ERABFailedtoSetupItemHOReqAckIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueMethodRule(v ERABFailedtoSetupItemHOReqAckIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *func(ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerListValueCodec, a0 ERABFailedtoSetupItemHOReqAckIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABFailedtoSetupListHOReqAckAPERValueFieldContext(v *ERABFailedtoSetupListHOReqAckAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupListHOReqAckAPERValueFieldReceived(v *ERABFailedtoSetupListHOReqAckAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABFailedtoSetupListHOReqAckAPERValueFieldReplay(v *ERABFailedtoSetupListHOReqAckAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABFailedtoSetupListHOReqAckAPERValueFieldWithoutReplay(v *ERABFailedtoSetupListHOReqAckAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldCapture(v *ERABFailedtoSetupListHOReqAckValueCodec) *func(ERABFailedtoSetupListHOReqAck, aper.DecodeState) (ERABFailedtoSetupListHOReqAck, aper.Snapshot) {
	return &v.capture
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldCompare(v *ERABFailedtoSetupListHOReqAckValueCodec) *func(ERABFailedtoSetupListHOReqAck, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldContext(v *ERABFailedtoSetupListHOReqAckValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldDecode(v *ERABFailedtoSetupListHOReqAckValueCodec) *func([]byte, aper.DecodeState) (ERABFailedtoSetupListHOReqAck, error) {
	return &v.decode
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldEncode(v *ERABFailedtoSetupListHOReqAckValueCodec) *func(ERABFailedtoSetupListHOReqAck, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecFieldPath(v *ERABFailedtoSetupListHOReqAckValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecMethodEncodeBudgetValue(v ERABFailedtoSetupListHOReqAckValueCodec, a0 ERABFailedtoSetupListHOReqAck, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABFailedtoSetupListHOReqAckValueCodecMethodEncodeChanged(v ERABFailedtoSetupListHOReqAckValueCodec, a0 ERABFailedtoSetupListHOReqAck, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemAPERValueFieldContext(v *ERABItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemAPERValueFieldReceived(v *ERABItemAPERValue) *aper.WireSpan { return &v.received }
func BridgeERABItemAPERValueFieldReplay(v *ERABItemAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeERABItemAPERValueFieldWithoutReplay(v *ERABItemAPERValue) *bool     { return &v.withoutReplay }
func BridgeERABItemERABItemIEBindingFieldCodec(v *ERABItemERABItemIEBinding) *ERABItemValueCodec {
	return &v.codec
}
func BridgeERABItemERABItemIEBindingFieldGet(v *ERABItemERABItemIEBinding) *func(*ERABItemIEValue) (*ERABItem, bool) {
	return &v.get
}
func BridgeERABItemERABItemIEBindingFieldInfo(v *ERABItemERABItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABItemERABItemIEBindingFieldInject(v *ERABItemERABItemIEBinding) *func(ERABItem) ERABItemIEValue {
	return &v.inject
}
func BridgeERABItemFieldExtCount(v *ERABItem) *int64                       { return &v.extCount }
func BridgeERABItemFieldExtData(v *ERABItem) *[][]byte                     { return &v.extData }
func BridgeERABItemFieldExtOrigin(v *ERABItem) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgeERABItemFieldExtPresent(v *ERABItem) *[]bool                    { return &v.extPresent }
func BridgeERABItemFieldExtWire(v *ERABItem) *[]aper.WireSpan              { return &v.extWire }
func BridgeERABItemFieldIEExtensionsIndef(v *ERABItem) *bool               { return &v.iEExtensionsIndef }
func BridgeERABItemFieldPerExtPadding(v *ERABItem) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgeERABItemFieldPerPadding(v *ERABItem) *aper.FinalPadding         { return &v.perPadding }
func BridgeERABItemFieldReceived(v *ERABItem) *bool                        { return &v.received }
func BridgeERABItemFieldReceivedAbsolute(v *ERABItem) *bool                { return &v.receivedAbsolute }
func BridgeERABItemFieldReceivedBytes(v *ERABItem) *aper.WireSpan          { return &v.receivedBytes }
func BridgeERABItemFieldReceivedLocation(v *ERABItem) *aper.Location       { return &v.receivedLocation }
func BridgeERABItemFieldReplay(v *ERABItem) *aper.Snapshot                 { return &v.replay }
func BridgeERABItemFieldStream(v *ERABItem) *aper.WireSpan                 { return &v.stream }
func BridgeERABItemFieldWithoutReplay(v *ERABItem) *bool                   { return &v.withoutReplay }
func BridgeERABItemIEContainerAPERValueFieldContext(v *ERABItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEContainerAPERValueFieldReceived(v *ERABItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABItemIEContainerAPERValueFieldReplay(v *ERABItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemIEContainerAPERValueFieldWithoutReplay(v *ERABItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABItemIEContainerValueCodecFieldCapture(v *ERABItemIEContainerValueCodec) *func(ERABItemIEContainer, aper.DecodeState) (ERABItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemIEContainerValueCodecFieldCompare(v *ERABItemIEContainerValueCodec) *func(ERABItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemIEContainerValueCodecFieldContext(v *ERABItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEContainerValueCodecFieldDecode(v *ERABItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABItemIEContainer, error) {
	return &v.decode
}
func BridgeERABItemIEContainerValueCodecFieldEncode(v *ERABItemIEContainerValueCodec) *func(ERABItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemIEContainerValueCodecFieldPath(v *ERABItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemIEContainerValueCodecMethodEncodeBudgetValue(v ERABItemIEContainerValueCodec, a0 ERABItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemIEContainerValueCodecMethodEncodeChanged(v ERABItemIEContainerValueCodec, a0 ERABItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemIEFieldAPERValueFieldContext(v *ERABItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEFieldAPERValueFieldReceived(v *ERABItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABItemIEFieldAPERValueFieldReplay(v *ERABItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemIEFieldAPERValueFieldWithoutReplay(v *ERABItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABItemIEFieldFieldReceived(v *ERABItemIEField) *aper.CompletePadding { return &v.received }
func BridgeERABItemIEFieldFieldReplay(v *ERABItemIEField) *aper.Snapshot          { return &v.replay }
func BridgeERABItemIEFieldFieldStream(v *ERABItemIEField) *aper.WireSpan          { return &v.stream }
func BridgeERABItemIEFieldFieldWithoutReplay(v *ERABItemIEField) *bool            { return &v.withoutReplay }
func BridgeERABItemIEFieldMethodMarshalAPERTo(v *ERABItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABItemIEFieldMethodUnmarshalAPERFrom(v *ERABItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABItemIEFieldValueCodecFieldCapture(v *ERABItemIEFieldValueCodec) *func(ERABItemIEField, aper.DecodeState) (ERABItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemIEFieldValueCodecFieldCompare(v *ERABItemIEFieldValueCodec) *func(ERABItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemIEFieldValueCodecFieldContext(v *ERABItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEFieldValueCodecFieldDecode(v *ERABItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABItemIEField, error) {
	return &v.decode
}
func BridgeERABItemIEFieldValueCodecFieldEncode(v *ERABItemIEFieldValueCodec) *func(ERABItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemIEFieldValueCodecFieldPath(v *ERABItemIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemIEFieldValueCodecMethodEncodeBudgetValue(v ERABItemIEFieldValueCodec, a0 ERABItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemIEFieldValueCodecMethodEncodeChanged(v ERABItemIEFieldValueCodec, a0 ERABItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemIETableMethodInfoERABItem(v ERABItemIETable) s00.FieldInfo {
	return v.infoERABItem()
}
func BridgeERABItemIEValueERABIEContainerListAPERValueFieldContext(v *ERABItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueERABIEContainerListAPERValueFieldReceived(v *ERABItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABItemIEValueERABIEContainerListAPERValueFieldReplay(v *ERABItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldCapture(v *ERABItemIEValueERABIEContainerListValueCodec) *func(ERABItemIEValueERABIEContainerList, aper.DecodeState) (ERABItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldCompare(v *ERABItemIEValueERABIEContainerListValueCodec) *func(ERABItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldContext(v *ERABItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldDecode(v *ERABItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldEncode(v *ERABItemIEValueERABIEContainerListValueCodec) *func(ERABItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemIEValueERABIEContainerListValueCodecFieldPath(v *ERABItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABItemIEValueERABIEContainerListValueCodec, a0 ERABItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABItemIEValueERABIEContainerListValueCodec, a0 ERABItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemIEValueFieldId(v *ERABItemIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgeERABItemIEValueFieldIsOpaque(v *ERABItemIEValue) *bool              { return &v.isOpaque }
func BridgeERABItemIEValueFieldOpaque(v *ERABItemIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeERABItemIEValueFieldReceived(v *ERABItemIEValue) *aper.WireSpan     { return &v.received }
func BridgeERABItemIEValueFieldReplay(v *ERABItemIEValue) *aper.Snapshot       { return &v.replay }
func BridgeERABItemIEValueFieldRowERABItem(v *ERABItemIEValue) **ERABItem      { return &v.rowERABItem }
func BridgeERABItemIEValueMethodCaptureSemantics(v ERABItemIEValue, a0 aper.SemanticCapture) ERABItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABItemIEValueMethodCompareSemantics(v ERABItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABItemIEValueMethodDecode(v ERABItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABItemIEValueMethodEncode(v ERABItemIEValue) ([]byte, error) { return v.encode() }
func BridgeERABItemIEValueMethodEncodeFresh(v ERABItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABItemIEValueMethodMatchesID(v ERABItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABItemIEValueMethodReason(v ERABItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABItemIEValueMethodRule(v ERABItemIEValue) aper.SourceRule { return v.rule() }
func BridgeERABItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *func(ERABItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABItemIEValueProtocolErrorIEContainerListValueCodec, a0 ERABItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABItemIEValueProtocolIEContainerListValueCodec) *func(ERABItemIEValueProtocolIEContainerList, aper.DecodeState) (ERABItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABItemIEValueProtocolIEContainerListValueCodec) *func(ERABItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABItemIEValueProtocolIEContainerListValueCodec) *func(ERABItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABItemIEValueProtocolIEContainerListValueCodec, a0 ERABItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABItemIEValueProtocolIEContainerListValueCodec, a0 ERABItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABItemMethodMarshalAPERBudget(v *ERABItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABItemMethodMarshalAPERBudgetValue(v *ERABItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABItemMethodMarshalAPERChanged(v *ERABItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABItemMethodMarshalAPERChangedValue(v *ERABItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABItemMethodMarshalAPERLegacy(v *ERABItem) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeERABItemMethodMarshalAPERNewValue(v *ERABItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABItemMethodMarshalAPERPlanned(v *ERABItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABItemMethodMarshalAPERTo(v *ERABItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABItemMethodUnmarshalAPERFrom(v *ERABItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABItemMethodUnmarshalAPERLegacy(v *ERABItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABItemMethodUnmarshalAPERWithOptions(v *ERABItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABItemValueCodecFieldCapture(v *ERABItemValueCodec) *func(ERABItem, aper.DecodeState) (ERABItem, aper.Snapshot) {
	return &v.capture
}
func BridgeERABItemValueCodecFieldCompare(v *ERABItemValueCodec) *func(ERABItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABItemValueCodecFieldContext(v *ERABItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABItemValueCodecFieldDecode(v *ERABItemValueCodec) *func([]byte, aper.DecodeState) (ERABItem, error) {
	return &v.decode
}
func BridgeERABItemValueCodecFieldEncode(v *ERABItemValueCodec) *func(ERABItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABItemValueCodecFieldPath(v *ERABItemValueCodec) *aper.Path { return &v.path }
func BridgeERABItemValueCodecMethodEncodeBudgetValue(v ERABItemValueCodec, a0 ERABItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABItemValueCodecMethodEncodeChanged(v ERABItemValueCodec, a0 ERABItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABListAPERValueFieldContext(v *ERABListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABListAPERValueFieldReceived(v *ERABListAPERValue) *aper.WireSpan { return &v.received }
func BridgeERABListAPERValueFieldReplay(v *ERABListAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeERABListAPERValueFieldWithoutReplay(v *ERABListAPERValue) *bool     { return &v.withoutReplay }
func BridgeERABListValueCodecFieldCapture(v *ERABListValueCodec) *func(ERABList, aper.DecodeState) (ERABList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABListValueCodecFieldCompare(v *ERABListValueCodec) *func(ERABList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABListValueCodecFieldContext(v *ERABListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABListValueCodecFieldDecode(v *ERABListValueCodec) *func([]byte, aper.DecodeState) (ERABList, error) {
	return &v.decode
}
func BridgeERABListValueCodecFieldEncode(v *ERABListValueCodec) *func(ERABList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABListValueCodecFieldPath(v *ERABListValueCodec) *aper.Path { return &v.path }
func BridgeERABListValueCodecMethodEncodeBudgetValue(v ERABListValueCodec, a0 ERABList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABListValueCodecMethodEncodeChanged(v ERABListValueCodec, a0 ERABList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfAPERValueFieldContext(v *ERABModifyItemBearerModConfAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfAPERValueFieldReceived(v *ERABModifyItemBearerModConfAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfAPERValueFieldReplay(v *ERABModifyItemBearerModConfAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfERABModifyItemBearerModConfIEBindingFieldCodec(v *ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) *ERABModifyItemBearerModConfValueCodec {
	return &v.codec
}
func BridgeERABModifyItemBearerModConfERABModifyItemBearerModConfIEBindingFieldGet(v *ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) *func(*ERABModifyItemBearerModConfIEValue) (*ERABModifyItemBearerModConf, bool) {
	return &v.get
}
func BridgeERABModifyItemBearerModConfERABModifyItemBearerModConfIEBindingFieldInfo(v *ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyItemBearerModConfERABModifyItemBearerModConfIEBindingFieldInject(v *ERABModifyItemBearerModConfERABModifyItemBearerModConfIEBinding) *func(ERABModifyItemBearerModConf) ERABModifyItemBearerModConfIEValue {
	return &v.inject
}
func BridgeERABModifyItemBearerModConfFieldExtCount(v *ERABModifyItemBearerModConf) *int64 {
	return &v.extCount
}
func BridgeERABModifyItemBearerModConfFieldExtData(v *ERABModifyItemBearerModConf) *[][]byte {
	return &v.extData
}
func BridgeERABModifyItemBearerModConfFieldExtOrigin(v *ERABModifyItemBearerModConf) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABModifyItemBearerModConfFieldExtPresent(v *ERABModifyItemBearerModConf) *[]bool {
	return &v.extPresent
}
func BridgeERABModifyItemBearerModConfFieldExtWire(v *ERABModifyItemBearerModConf) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABModifyItemBearerModConfFieldIEExtensionsIndef(v *ERABModifyItemBearerModConf) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABModifyItemBearerModConfFieldPerExtPadding(v *ERABModifyItemBearerModConf) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABModifyItemBearerModConfFieldPerPadding(v *ERABModifyItemBearerModConf) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModifyItemBearerModConfFieldReceived(v *ERABModifyItemBearerModConf) *bool {
	return &v.received
}
func BridgeERABModifyItemBearerModConfFieldReceivedAbsolute(v *ERABModifyItemBearerModConf) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyItemBearerModConfFieldReceivedBytes(v *ERABModifyItemBearerModConf) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyItemBearerModConfFieldReceivedLocation(v *ERABModifyItemBearerModConf) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyItemBearerModConfFieldReplay(v *ERABModifyItemBearerModConf) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfFieldStream(v *ERABModifyItemBearerModConf) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyItemBearerModConfFieldWithoutReplay(v *ERABModifyItemBearerModConf) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEContainerAPERValueFieldContext(v *ERABModifyItemBearerModConfIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEContainerAPERValueFieldReceived(v *ERABModifyItemBearerModConfIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEContainerAPERValueFieldReplay(v *ERABModifyItemBearerModConfIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEContainerAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCapture(v *ERABModifyItemBearerModConfIEContainerValueCodec) *func(ERABModifyItemBearerModConfIEContainer, aper.DecodeState) (ERABModifyItemBearerModConfIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldCompare(v *ERABModifyItemBearerModConfIEContainerValueCodec) *func(ERABModifyItemBearerModConfIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldContext(v *ERABModifyItemBearerModConfIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldDecode(v *ERABModifyItemBearerModConfIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEContainer, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldEncode(v *ERABModifyItemBearerModConfIEContainerValueCodec) *func(ERABModifyItemBearerModConfIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecFieldPath(v *ERABModifyItemBearerModConfIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfIEContainerValueCodec, a0 ERABModifyItemBearerModConfIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfIEContainerValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfIEContainerValueCodec, a0 ERABModifyItemBearerModConfIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfIEFieldAPERValueFieldContext(v *ERABModifyItemBearerModConfIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEFieldAPERValueFieldReceived(v *ERABModifyItemBearerModConfIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEFieldAPERValueFieldReplay(v *ERABModifyItemBearerModConfIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEFieldAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEFieldFieldReceived(v *ERABModifyItemBearerModConfIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEFieldFieldReplay(v *ERABModifyItemBearerModConfIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEFieldFieldStream(v *ERABModifyItemBearerModConfIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyItemBearerModConfIEFieldFieldWithoutReplay(v *ERABModifyItemBearerModConfIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEFieldMethodMarshalAPERTo(v *ERABModifyItemBearerModConfIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModConfIEFieldMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModConfIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCapture(v *ERABModifyItemBearerModConfIEFieldValueCodec) *func(ERABModifyItemBearerModConfIEField, aper.DecodeState) (ERABModifyItemBearerModConfIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldCompare(v *ERABModifyItemBearerModConfIEFieldValueCodec) *func(ERABModifyItemBearerModConfIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldContext(v *ERABModifyItemBearerModConfIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldDecode(v *ERABModifyItemBearerModConfIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEField, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldEncode(v *ERABModifyItemBearerModConfIEFieldValueCodec) *func(ERABModifyItemBearerModConfIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecFieldPath(v *ERABModifyItemBearerModConfIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfIEFieldValueCodec, a0 ERABModifyItemBearerModConfIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfIEFieldValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfIEFieldValueCodec, a0 ERABModifyItemBearerModConfIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfIETableMethodInfoERABModifyItemBearerModConf(v ERABModifyItemBearerModConfIETable) s00.FieldInfo {
	return v.infoERABModifyItemBearerModConf()
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfIEValueERABIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfIEValueFieldId(v *ERABModifyItemBearerModConfIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModifyItemBearerModConfIEValueFieldIsOpaque(v *ERABModifyItemBearerModConfIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModifyItemBearerModConfIEValueFieldOpaque(v *ERABModifyItemBearerModConfIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModifyItemBearerModConfIEValueFieldReceived(v *ERABModifyItemBearerModConfIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEValueFieldReplay(v *ERABModifyItemBearerModConfIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEValueFieldRowERABModifyItemBearerModConf(v *ERABModifyItemBearerModConfIEValue) **ERABModifyItemBearerModConf {
	return &v.rowERABModifyItemBearerModConf
}
func BridgeERABModifyItemBearerModConfIEValueMethodCaptureSemantics(v ERABModifyItemBearerModConfIEValue, a0 aper.SemanticCapture) ERABModifyItemBearerModConfIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModifyItemBearerModConfIEValueMethodCompareSemantics(v ERABModifyItemBearerModConfIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModifyItemBearerModConfIEValueMethodDecode(v ERABModifyItemBearerModConfIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModifyItemBearerModConfIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModifyItemBearerModConfIEValueMethodEncode(v ERABModifyItemBearerModConfIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModifyItemBearerModConfIEValueMethodEncodeFresh(v ERABModifyItemBearerModConfIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModifyItemBearerModConfIEValueMethodMatchesID(v ERABModifyItemBearerModConfIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModifyItemBearerModConfIEValueMethodReason(v ERABModifyItemBearerModConfIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModifyItemBearerModConfIEValueMethodRule(v ERABModifyItemBearerModConfIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConfIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModConfIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfIEValueProtocolIEContainerListValueCodec, a0 ERABModifyItemBearerModConfIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERBudget(v *ERABModifyItemBearerModConf, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERBudgetValue(v *ERABModifyItemBearerModConf, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERChanged(v *ERABModifyItemBearerModConf, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERChangedValue(v *ERABModifyItemBearerModConf, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERLegacy(v *ERABModifyItemBearerModConf) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERNewValue(v *ERABModifyItemBearerModConf, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERPlanned(v *ERABModifyItemBearerModConf, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfMethodMarshalAPERTo(v *ERABModifyItemBearerModConf, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModConfMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModConf, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModConfMethodUnmarshalAPERLegacy(v *ERABModifyItemBearerModConf, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModifyItemBearerModConfMethodUnmarshalAPERWithOptions(v *ERABModifyItemBearerModConf, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModifyItemBearerModConfValueCodecFieldCapture(v *ERABModifyItemBearerModConfValueCodec) *func(ERABModifyItemBearerModConf, aper.DecodeState) (ERABModifyItemBearerModConf, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModConfValueCodecFieldCompare(v *ERABModifyItemBearerModConfValueCodec) *func(ERABModifyItemBearerModConf, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModConfValueCodecFieldContext(v *ERABModifyItemBearerModConfValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModConfValueCodecFieldDecode(v *ERABModifyItemBearerModConfValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModConf, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModConfValueCodecFieldEncode(v *ERABModifyItemBearerModConfValueCodec) *func(ERABModifyItemBearerModConf, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModConfValueCodecFieldPath(v *ERABModifyItemBearerModConfValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModConfValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModConfValueCodec, a0 ERABModifyItemBearerModConf, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModConfValueCodecMethodEncodeChanged(v ERABModifyItemBearerModConfValueCodec, a0 ERABModifyItemBearerModConf, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResAPERValueFieldContext(v *ERABModifyItemBearerModResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResAPERValueFieldReceived(v *ERABModifyItemBearerModResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResAPERValueFieldReplay(v *ERABModifyItemBearerModResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResERABModifyItemBearerModResIEBindingFieldCodec(v *ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) *ERABModifyItemBearerModResValueCodec {
	return &v.codec
}
func BridgeERABModifyItemBearerModResERABModifyItemBearerModResIEBindingFieldGet(v *ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) *func(*ERABModifyItemBearerModResIEValue) (*ERABModifyItemBearerModRes, bool) {
	return &v.get
}
func BridgeERABModifyItemBearerModResERABModifyItemBearerModResIEBindingFieldInfo(v *ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModifyItemBearerModResERABModifyItemBearerModResIEBindingFieldInject(v *ERABModifyItemBearerModResERABModifyItemBearerModResIEBinding) *func(ERABModifyItemBearerModRes) ERABModifyItemBearerModResIEValue {
	return &v.inject
}
func BridgeERABModifyItemBearerModResFieldExtCount(v *ERABModifyItemBearerModRes) *int64 {
	return &v.extCount
}
func BridgeERABModifyItemBearerModResFieldExtData(v *ERABModifyItemBearerModRes) *[][]byte {
	return &v.extData
}
func BridgeERABModifyItemBearerModResFieldExtOrigin(v *ERABModifyItemBearerModRes) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABModifyItemBearerModResFieldExtPresent(v *ERABModifyItemBearerModRes) *[]bool {
	return &v.extPresent
}
func BridgeERABModifyItemBearerModResFieldExtWire(v *ERABModifyItemBearerModRes) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABModifyItemBearerModResFieldIEExtensionsIndef(v *ERABModifyItemBearerModRes) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABModifyItemBearerModResFieldPerExtPadding(v *ERABModifyItemBearerModRes) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABModifyItemBearerModResFieldPerPadding(v *ERABModifyItemBearerModRes) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABModifyItemBearerModResFieldReceived(v *ERABModifyItemBearerModRes) *bool {
	return &v.received
}
func BridgeERABModifyItemBearerModResFieldReceivedAbsolute(v *ERABModifyItemBearerModRes) *bool {
	return &v.receivedAbsolute
}
func BridgeERABModifyItemBearerModResFieldReceivedBytes(v *ERABModifyItemBearerModRes) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABModifyItemBearerModResFieldReceivedLocation(v *ERABModifyItemBearerModRes) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABModifyItemBearerModResFieldReplay(v *ERABModifyItemBearerModRes) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResFieldStream(v *ERABModifyItemBearerModRes) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyItemBearerModResFieldWithoutReplay(v *ERABModifyItemBearerModRes) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEContainerAPERValueFieldContext(v *ERABModifyItemBearerModResIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEContainerAPERValueFieldReceived(v *ERABModifyItemBearerModResIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEContainerAPERValueFieldReplay(v *ERABModifyItemBearerModResIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEContainerAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCapture(v *ERABModifyItemBearerModResIEContainerValueCodec) *func(ERABModifyItemBearerModResIEContainer, aper.DecodeState) (ERABModifyItemBearerModResIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldCompare(v *ERABModifyItemBearerModResIEContainerValueCodec) *func(ERABModifyItemBearerModResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldContext(v *ERABModifyItemBearerModResIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldDecode(v *ERABModifyItemBearerModResIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEContainer, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldEncode(v *ERABModifyItemBearerModResIEContainerValueCodec) *func(ERABModifyItemBearerModResIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecFieldPath(v *ERABModifyItemBearerModResIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResIEContainerValueCodec, a0 ERABModifyItemBearerModResIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResIEContainerValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResIEContainerValueCodec, a0 ERABModifyItemBearerModResIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResIEFieldAPERValueFieldContext(v *ERABModifyItemBearerModResIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEFieldAPERValueFieldReceived(v *ERABModifyItemBearerModResIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEFieldAPERValueFieldReplay(v *ERABModifyItemBearerModResIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEFieldAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEFieldFieldReceived(v *ERABModifyItemBearerModResIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEFieldFieldReplay(v *ERABModifyItemBearerModResIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEFieldFieldStream(v *ERABModifyItemBearerModResIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModifyItemBearerModResIEFieldFieldWithoutReplay(v *ERABModifyItemBearerModResIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEFieldMethodMarshalAPERTo(v *ERABModifyItemBearerModResIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModResIEFieldMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModResIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCapture(v *ERABModifyItemBearerModResIEFieldValueCodec) *func(ERABModifyItemBearerModResIEField, aper.DecodeState) (ERABModifyItemBearerModResIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldCompare(v *ERABModifyItemBearerModResIEFieldValueCodec) *func(ERABModifyItemBearerModResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldContext(v *ERABModifyItemBearerModResIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldDecode(v *ERABModifyItemBearerModResIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEField, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldEncode(v *ERABModifyItemBearerModResIEFieldValueCodec) *func(ERABModifyItemBearerModResIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecFieldPath(v *ERABModifyItemBearerModResIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResIEFieldValueCodec, a0 ERABModifyItemBearerModResIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResIEFieldValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResIEFieldValueCodec, a0 ERABModifyItemBearerModResIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResIETableMethodInfoERABModifyItemBearerModRes(v ERABModifyItemBearerModResIETable) s00.FieldInfo {
	return v.infoERABModifyItemBearerModRes()
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueERABIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResIEValueERABIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResIEValueFieldId(v *ERABModifyItemBearerModResIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModifyItemBearerModResIEValueFieldIsOpaque(v *ERABModifyItemBearerModResIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModifyItemBearerModResIEValueFieldOpaque(v *ERABModifyItemBearerModResIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModifyItemBearerModResIEValueFieldReceived(v *ERABModifyItemBearerModResIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEValueFieldReplay(v *ERABModifyItemBearerModResIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEValueFieldRowERABModifyItemBearerModRes(v *ERABModifyItemBearerModResIEValue) **ERABModifyItemBearerModRes {
	return &v.rowERABModifyItemBearerModRes
}
func BridgeERABModifyItemBearerModResIEValueMethodCaptureSemantics(v ERABModifyItemBearerModResIEValue, a0 aper.SemanticCapture) ERABModifyItemBearerModResIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModifyItemBearerModResIEValueMethodCompareSemantics(v ERABModifyItemBearerModResIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModifyItemBearerModResIEValueMethodDecode(v ERABModifyItemBearerModResIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModifyItemBearerModResIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModifyItemBearerModResIEValueMethodEncode(v ERABModifyItemBearerModResIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModifyItemBearerModResIEValueMethodEncodeFresh(v ERABModifyItemBearerModResIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModifyItemBearerModResIEValueMethodMatchesID(v ERABModifyItemBearerModResIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModifyItemBearerModResIEValueMethodReason(v ERABModifyItemBearerModResIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModifyItemBearerModResIEValueMethodRule(v ERABModifyItemBearerModResIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModResIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *func(ERABModifyItemBearerModResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResIEValueProtocolIEContainerListValueCodec, a0 ERABModifyItemBearerModResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERBudget(v *ERABModifyItemBearerModRes, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERBudgetValue(v *ERABModifyItemBearerModRes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERChanged(v *ERABModifyItemBearerModRes, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERChangedValue(v *ERABModifyItemBearerModRes, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERLegacy(v *ERABModifyItemBearerModRes) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERNewValue(v *ERABModifyItemBearerModRes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERPlanned(v *ERABModifyItemBearerModRes, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResMethodMarshalAPERTo(v *ERABModifyItemBearerModRes, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModifyItemBearerModResMethodUnmarshalAPERFrom(v *ERABModifyItemBearerModRes, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModifyItemBearerModResMethodUnmarshalAPERLegacy(v *ERABModifyItemBearerModRes, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABModifyItemBearerModResMethodUnmarshalAPERWithOptions(v *ERABModifyItemBearerModRes, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABModifyItemBearerModResValueCodecFieldCapture(v *ERABModifyItemBearerModResValueCodec) *func(ERABModifyItemBearerModRes, aper.DecodeState) (ERABModifyItemBearerModRes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyItemBearerModResValueCodecFieldCompare(v *ERABModifyItemBearerModResValueCodec) *func(ERABModifyItemBearerModRes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyItemBearerModResValueCodecFieldContext(v *ERABModifyItemBearerModResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyItemBearerModResValueCodecFieldDecode(v *ERABModifyItemBearerModResValueCodec) *func([]byte, aper.DecodeState) (ERABModifyItemBearerModRes, error) {
	return &v.decode
}
func BridgeERABModifyItemBearerModResValueCodecFieldEncode(v *ERABModifyItemBearerModResValueCodec) *func(ERABModifyItemBearerModRes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyItemBearerModResValueCodecFieldPath(v *ERABModifyItemBearerModResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyItemBearerModResValueCodecMethodEncodeBudgetValue(v ERABModifyItemBearerModResValueCodec, a0 ERABModifyItemBearerModRes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyItemBearerModResValueCodecMethodEncodeChanged(v ERABModifyItemBearerModResValueCodec, a0 ERABModifyItemBearerModRes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyListBearerModConfAPERValueFieldContext(v *ERABModifyListBearerModConfAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyListBearerModConfAPERValueFieldReceived(v *ERABModifyListBearerModConfAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyListBearerModConfAPERValueFieldReplay(v *ERABModifyListBearerModConfAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyListBearerModConfAPERValueFieldWithoutReplay(v *ERABModifyListBearerModConfAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyListBearerModConfValueCodecFieldCapture(v *ERABModifyListBearerModConfValueCodec) *func(ERABModifyListBearerModConf, aper.DecodeState) (ERABModifyListBearerModConf, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyListBearerModConfValueCodecFieldCompare(v *ERABModifyListBearerModConfValueCodec) *func(ERABModifyListBearerModConf, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyListBearerModConfValueCodecFieldContext(v *ERABModifyListBearerModConfValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyListBearerModConfValueCodecFieldDecode(v *ERABModifyListBearerModConfValueCodec) *func([]byte, aper.DecodeState) (ERABModifyListBearerModConf, error) {
	return &v.decode
}
func BridgeERABModifyListBearerModConfValueCodecFieldEncode(v *ERABModifyListBearerModConfValueCodec) *func(ERABModifyListBearerModConf, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyListBearerModConfValueCodecFieldPath(v *ERABModifyListBearerModConfValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyListBearerModConfValueCodecMethodEncodeBudgetValue(v ERABModifyListBearerModConfValueCodec, a0 ERABModifyListBearerModConf, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyListBearerModConfValueCodecMethodEncodeChanged(v ERABModifyListBearerModConfValueCodec, a0 ERABModifyListBearerModConf, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModifyListBearerModResAPERValueFieldContext(v *ERABModifyListBearerModResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyListBearerModResAPERValueFieldReceived(v *ERABModifyListBearerModResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModifyListBearerModResAPERValueFieldReplay(v *ERABModifyListBearerModResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModifyListBearerModResAPERValueFieldWithoutReplay(v *ERABModifyListBearerModResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModifyListBearerModResValueCodecFieldCapture(v *ERABModifyListBearerModResValueCodec) *func(ERABModifyListBearerModRes, aper.DecodeState) (ERABModifyListBearerModRes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyListBearerModResValueCodecFieldCompare(v *ERABModifyListBearerModResValueCodec) *func(ERABModifyListBearerModRes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyListBearerModResValueCodecFieldContext(v *ERABModifyListBearerModResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyListBearerModResValueCodecFieldDecode(v *ERABModifyListBearerModResValueCodec) *func([]byte, aper.DecodeState) (ERABModifyListBearerModRes, error) {
	return &v.decode
}
func BridgeERABModifyListBearerModResValueCodecFieldEncode(v *ERABModifyListBearerModResValueCodec) *func(ERABModifyListBearerModRes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyListBearerModResValueCodecFieldPath(v *ERABModifyListBearerModResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModifyListBearerModResValueCodecMethodEncodeBudgetValue(v ERABModifyListBearerModResValueCodec, a0 ERABModifyListBearerModRes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModifyListBearerModResValueCodecMethodEncodeChanged(v ERABModifyListBearerModResValueCodec, a0 ERABModifyListBearerModRes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBindingFieldCodec(v *ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) *ERABNotToBeModifiedItemBearerModIndValueCodec {
	return &v.codec
}
func BridgeERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBindingFieldGet(v *ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) *func(*ERABNotToBeModifiedItemBearerModIndIEValue) (*ERABNotToBeModifiedItemBearerModInd, bool) {
	return &v.get
}
func BridgeERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBindingFieldInfo(v *ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBindingFieldInject(v *ERABNotToBeModifiedItemBearerModIndERABNotToBeModifiedItemBearerModIndIEBinding) *func(ERABNotToBeModifiedItemBearerModInd) ERABNotToBeModifiedItemBearerModIndIEValue {
	return &v.inject
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldExtCount(v *ERABNotToBeModifiedItemBearerModInd) *int64 {
	return &v.extCount
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldExtData(v *ERABNotToBeModifiedItemBearerModInd) *[][]byte {
	return &v.extData
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldExtOrigin(v *ERABNotToBeModifiedItemBearerModInd) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldExtPresent(v *ERABNotToBeModifiedItemBearerModInd) *[]bool {
	return &v.extPresent
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldExtWire(v *ERABNotToBeModifiedItemBearerModInd) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldIEExtensionsIndef(v *ERABNotToBeModifiedItemBearerModInd) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldPerExtPadding(v *ERABNotToBeModifiedItemBearerModInd) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldPerPadding(v *ERABNotToBeModifiedItemBearerModInd) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldReceived(v *ERABNotToBeModifiedItemBearerModInd) *bool {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldReceivedAbsolute(v *ERABNotToBeModifiedItemBearerModInd) *bool {
	return &v.receivedAbsolute
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldReceivedBytes(v *ERABNotToBeModifiedItemBearerModInd) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldReceivedLocation(v *ERABNotToBeModifiedItemBearerModInd) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldReplay(v *ERABNotToBeModifiedItemBearerModInd) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldStream(v *ERABNotToBeModifiedItemBearerModInd) *aper.WireSpan {
	return &v.stream
}
func BridgeERABNotToBeModifiedItemBearerModIndFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModInd) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEContainer, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEContainer, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEContainerValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndIEContainerValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldStream(v *ERABNotToBeModifiedItemBearerModIndIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodMarshalAPERTo(v *ERABNotToBeModifiedItemBearerModIndIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldMethodUnmarshalAPERFrom(v *ERABNotToBeModifiedItemBearerModIndIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEField, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEField, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEFieldValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndIEFieldValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndIETableMethodInfoERABNotToBeModifiedItemBearerModInd(v ERABNotToBeModifiedItemBearerModIndIETable) s00.FieldInfo {
	return v.infoERABNotToBeModifiedItemBearerModInd()
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldId(v *ERABNotToBeModifiedItemBearerModIndIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldIsOpaque(v *ERABNotToBeModifiedItemBearerModIndIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldOpaque(v *ERABNotToBeModifiedItemBearerModIndIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueFieldRowERABNotToBeModifiedItemBearerModInd(v *ERABNotToBeModifiedItemBearerModIndIEValue) **ERABNotToBeModifiedItemBearerModInd {
	return &v.rowERABNotToBeModifiedItemBearerModInd
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCaptureSemantics(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 aper.SemanticCapture) ERABNotToBeModifiedItemBearerModIndIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodCompareSemantics(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodDecode(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABNotToBeModifiedItemBearerModIndIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodEncode(v ERABNotToBeModifiedItemBearerModIndIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodEncodeFresh(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodMatchesID(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodReason(v ERABNotToBeModifiedItemBearerModIndIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueMethodRule(v ERABNotToBeModifiedItemBearerModIndIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *func(ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerListValueCodec, a0 ERABNotToBeModifiedItemBearerModIndIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERBudget(v *ERABNotToBeModifiedItemBearerModInd, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERBudgetValue(v *ERABNotToBeModifiedItemBearerModInd, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERChanged(v *ERABNotToBeModifiedItemBearerModInd, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERChangedValue(v *ERABNotToBeModifiedItemBearerModInd, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERLegacy(v *ERABNotToBeModifiedItemBearerModInd) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERNewValue(v *ERABNotToBeModifiedItemBearerModInd, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERPlanned(v *ERABNotToBeModifiedItemBearerModInd, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodMarshalAPERTo(v *ERABNotToBeModifiedItemBearerModInd, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodUnmarshalAPERFrom(v *ERABNotToBeModifiedItemBearerModInd, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodUnmarshalAPERLegacy(v *ERABNotToBeModifiedItemBearerModInd, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABNotToBeModifiedItemBearerModIndMethodUnmarshalAPERWithOptions(v *ERABNotToBeModifiedItemBearerModInd, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldCapture(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *func(ERABNotToBeModifiedItemBearerModInd, aper.DecodeState) (ERABNotToBeModifiedItemBearerModInd, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldCompare(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *func(ERABNotToBeModifiedItemBearerModInd, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldContext(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldDecode(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedItemBearerModInd, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldEncode(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *func(ERABNotToBeModifiedItemBearerModInd, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecFieldPath(v *ERABNotToBeModifiedItemBearerModIndValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedItemBearerModIndValueCodec, a0 ERABNotToBeModifiedItemBearerModInd, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedItemBearerModIndValueCodecMethodEncodeChanged(v ERABNotToBeModifiedItemBearerModIndValueCodec, a0 ERABNotToBeModifiedItemBearerModInd, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABNotToBeModifiedListBearerModIndAPERValueFieldContext(v *ERABNotToBeModifiedListBearerModIndAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedListBearerModIndAPERValueFieldReceived(v *ERABNotToBeModifiedListBearerModIndAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABNotToBeModifiedListBearerModIndAPERValueFieldReplay(v *ERABNotToBeModifiedListBearerModIndAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABNotToBeModifiedListBearerModIndAPERValueFieldWithoutReplay(v *ERABNotToBeModifiedListBearerModIndAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCapture(v *ERABNotToBeModifiedListBearerModIndValueCodec) *func(ERABNotToBeModifiedListBearerModInd, aper.DecodeState) (ERABNotToBeModifiedListBearerModInd, aper.Snapshot) {
	return &v.capture
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldCompare(v *ERABNotToBeModifiedListBearerModIndValueCodec) *func(ERABNotToBeModifiedListBearerModInd, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldContext(v *ERABNotToBeModifiedListBearerModIndValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldDecode(v *ERABNotToBeModifiedListBearerModIndValueCodec) *func([]byte, aper.DecodeState) (ERABNotToBeModifiedListBearerModInd, error) {
	return &v.decode
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldEncode(v *ERABNotToBeModifiedListBearerModIndValueCodec) *func(ERABNotToBeModifiedListBearerModInd, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldPath(v *ERABNotToBeModifiedListBearerModIndValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecMethodEncodeBudgetValue(v ERABNotToBeModifiedListBearerModIndValueCodec, a0 ERABNotToBeModifiedListBearerModInd, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABNotToBeModifiedListBearerModIndValueCodecMethodEncodeChanged(v ERABNotToBeModifiedListBearerModIndValueCodec, a0 ERABNotToBeModifiedListBearerModInd, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompAPERValueFieldContext(v *ERABReleaseItemBearerRelCompAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBindingFieldCodec(v *ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) *ERABReleaseItemBearerRelCompValueCodec {
	return &v.codec
}
func BridgeERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBindingFieldGet(v *ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) *func(*ERABReleaseItemBearerRelCompIEValue) (*ERABReleaseItemBearerRelComp, bool) {
	return &v.get
}
func BridgeERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBindingFieldInfo(v *ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBindingFieldInject(v *ERABReleaseItemBearerRelCompERABReleaseItemBearerRelCompIEBinding) *func(ERABReleaseItemBearerRelComp) ERABReleaseItemBearerRelCompIEValue {
	return &v.inject
}
func BridgeERABReleaseItemBearerRelCompFieldExtCount(v *ERABReleaseItemBearerRelComp) *int64 {
	return &v.extCount
}
func BridgeERABReleaseItemBearerRelCompFieldExtData(v *ERABReleaseItemBearerRelComp) *[][]byte {
	return &v.extData
}
func BridgeERABReleaseItemBearerRelCompFieldExtOrigin(v *ERABReleaseItemBearerRelComp) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABReleaseItemBearerRelCompFieldExtPresent(v *ERABReleaseItemBearerRelComp) *[]bool {
	return &v.extPresent
}
func BridgeERABReleaseItemBearerRelCompFieldExtWire(v *ERABReleaseItemBearerRelComp) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABReleaseItemBearerRelCompFieldIEExtensionsIndef(v *ERABReleaseItemBearerRelComp) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABReleaseItemBearerRelCompFieldPerExtPadding(v *ERABReleaseItemBearerRelComp) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABReleaseItemBearerRelCompFieldPerPadding(v *ERABReleaseItemBearerRelComp) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABReleaseItemBearerRelCompFieldReceived(v *ERABReleaseItemBearerRelComp) *bool {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompFieldReceivedAbsolute(v *ERABReleaseItemBearerRelComp) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseItemBearerRelCompFieldReceivedBytes(v *ERABReleaseItemBearerRelComp) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseItemBearerRelCompFieldReceivedLocation(v *ERABReleaseItemBearerRelComp) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseItemBearerRelCompFieldReplay(v *ERABReleaseItemBearerRelComp) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompFieldStream(v *ERABReleaseItemBearerRelComp) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseItemBearerRelCompFieldWithoutReplay(v *ERABReleaseItemBearerRelComp) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEContainerAPERValueFieldContext(v *ERABReleaseItemBearerRelCompIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEContainerAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEContainerAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEContainerAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *func(ERABReleaseItemBearerRelCompIEContainer, aper.DecodeState) (ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *func(ERABReleaseItemBearerRelCompIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldContext(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEContainer, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *func(ERABReleaseItemBearerRelCompIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecFieldPath(v *ERABReleaseItemBearerRelCompIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompIEContainerValueCodec, a0 ERABReleaseItemBearerRelCompIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompIEContainerValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompIEContainerValueCodec, a0 ERABReleaseItemBearerRelCompIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompIEFieldAPERValueFieldContext(v *ERABReleaseItemBearerRelCompIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEFieldAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEFieldAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEFieldAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEFieldFieldReceived(v *ERABReleaseItemBearerRelCompIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEFieldFieldReplay(v *ERABReleaseItemBearerRelCompIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEFieldFieldStream(v *ERABReleaseItemBearerRelCompIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABReleaseItemBearerRelCompIEFieldFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEFieldMethodMarshalAPERTo(v *ERABReleaseItemBearerRelCompIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseItemBearerRelCompIEFieldMethodUnmarshalAPERFrom(v *ERABReleaseItemBearerRelCompIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *func(ERABReleaseItemBearerRelCompIEField, aper.DecodeState) (ERABReleaseItemBearerRelCompIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *func(ERABReleaseItemBearerRelCompIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldContext(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEField, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *func(ERABReleaseItemBearerRelCompIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecFieldPath(v *ERABReleaseItemBearerRelCompIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompIEFieldValueCodec, a0 ERABReleaseItemBearerRelCompIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompIEFieldValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompIEFieldValueCodec, a0 ERABReleaseItemBearerRelCompIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompIETableMethodInfoERABReleaseItemBearerRelComp(v ERABReleaseItemBearerRelCompIETable) s00.FieldInfo {
	return v.infoERABReleaseItemBearerRelComp()
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValueFieldContext(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldContext(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecFieldPath(v *ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompIEValueERABIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldId(v *ERABReleaseItemBearerRelCompIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldIsOpaque(v *ERABReleaseItemBearerRelCompIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldOpaque(v *ERABReleaseItemBearerRelCompIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldReceived(v *ERABReleaseItemBearerRelCompIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldReplay(v *ERABReleaseItemBearerRelCompIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEValueFieldRowERABReleaseItemBearerRelComp(v *ERABReleaseItemBearerRelCompIEValue) **ERABReleaseItemBearerRelComp {
	return &v.rowERABReleaseItemBearerRelComp
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodCaptureSemantics(v ERABReleaseItemBearerRelCompIEValue, a0 aper.SemanticCapture) ERABReleaseItemBearerRelCompIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodCompareSemantics(v ERABReleaseItemBearerRelCompIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodDecode(v ERABReleaseItemBearerRelCompIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABReleaseItemBearerRelCompIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodEncode(v ERABReleaseItemBearerRelCompIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodEncodeFresh(v ERABReleaseItemBearerRelCompIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodMatchesID(v ERABReleaseItemBearerRelCompIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodReason(v ERABReleaseItemBearerRelCompIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABReleaseItemBearerRelCompIEValueMethodRule(v ERABReleaseItemBearerRelCompIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *func(ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompIEValueProtocolIEContainerListValueCodec, a0 ERABReleaseItemBearerRelCompIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERBudget(v *ERABReleaseItemBearerRelComp, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERBudgetValue(v *ERABReleaseItemBearerRelComp, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERChanged(v *ERABReleaseItemBearerRelComp, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERChangedValue(v *ERABReleaseItemBearerRelComp, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERLegacy(v *ERABReleaseItemBearerRelComp) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERNewValue(v *ERABReleaseItemBearerRelComp, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERPlanned(v *ERABReleaseItemBearerRelComp, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompMethodMarshalAPERTo(v *ERABReleaseItemBearerRelComp, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseItemBearerRelCompMethodUnmarshalAPERFrom(v *ERABReleaseItemBearerRelComp, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseItemBearerRelCompMethodUnmarshalAPERLegacy(v *ERABReleaseItemBearerRelComp, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABReleaseItemBearerRelCompMethodUnmarshalAPERWithOptions(v *ERABReleaseItemBearerRelComp, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldCapture(v *ERABReleaseItemBearerRelCompValueCodec) *func(ERABReleaseItemBearerRelComp, aper.DecodeState) (ERABReleaseItemBearerRelComp, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldCompare(v *ERABReleaseItemBearerRelCompValueCodec) *func(ERABReleaseItemBearerRelComp, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldContext(v *ERABReleaseItemBearerRelCompValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldDecode(v *ERABReleaseItemBearerRelCompValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseItemBearerRelComp, error) {
	return &v.decode
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldEncode(v *ERABReleaseItemBearerRelCompValueCodec) *func(ERABReleaseItemBearerRelComp, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseItemBearerRelCompValueCodecFieldPath(v *ERABReleaseItemBearerRelCompValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseItemBearerRelCompValueCodecMethodEncodeBudgetValue(v ERABReleaseItemBearerRelCompValueCodec, a0 ERABReleaseItemBearerRelComp, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseItemBearerRelCompValueCodecMethodEncodeChanged(v ERABReleaseItemBearerRelCompValueCodec, a0 ERABReleaseItemBearerRelComp, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABReleaseListBearerRelCompAPERValueFieldContext(v *ERABReleaseListBearerRelCompAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseListBearerRelCompAPERValueFieldReceived(v *ERABReleaseListBearerRelCompAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseListBearerRelCompAPERValueFieldReplay(v *ERABReleaseListBearerRelCompAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseListBearerRelCompAPERValueFieldWithoutReplay(v *ERABReleaseListBearerRelCompAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldCapture(v *ERABReleaseListBearerRelCompValueCodec) *func(ERABReleaseListBearerRelComp, aper.DecodeState) (ERABReleaseListBearerRelComp, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldCompare(v *ERABReleaseListBearerRelCompValueCodec) *func(ERABReleaseListBearerRelComp, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldContext(v *ERABReleaseListBearerRelCompValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldDecode(v *ERABReleaseListBearerRelCompValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseListBearerRelComp, error) {
	return &v.decode
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldEncode(v *ERABReleaseListBearerRelCompValueCodec) *func(ERABReleaseListBearerRelComp, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseListBearerRelCompValueCodecFieldPath(v *ERABReleaseListBearerRelCompValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseListBearerRelCompValueCodecMethodEncodeBudgetValue(v ERABReleaseListBearerRelCompValueCodec, a0 ERABReleaseListBearerRelComp, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseListBearerRelCompValueCodecMethodEncodeChanged(v ERABReleaseListBearerRelCompValueCodec, a0 ERABReleaseListBearerRelComp, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResAPERValueFieldContext(v *ERABSetupItemBearerSUResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResAPERValueFieldReceived(v *ERABSetupItemBearerSUResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResAPERValueFieldReplay(v *ERABSetupItemBearerSUResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResERABSetupItemBearerSUResIEBindingFieldCodec(v *ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) *ERABSetupItemBearerSUResValueCodec {
	return &v.codec
}
func BridgeERABSetupItemBearerSUResERABSetupItemBearerSUResIEBindingFieldGet(v *ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) *func(*ERABSetupItemBearerSUResIEValue) (*ERABSetupItemBearerSURes, bool) {
	return &v.get
}
func BridgeERABSetupItemBearerSUResERABSetupItemBearerSUResIEBindingFieldInfo(v *ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupItemBearerSUResERABSetupItemBearerSUResIEBindingFieldInject(v *ERABSetupItemBearerSUResERABSetupItemBearerSUResIEBinding) *func(ERABSetupItemBearerSURes) ERABSetupItemBearerSUResIEValue {
	return &v.inject
}
func BridgeERABSetupItemBearerSUResFieldExtCount(v *ERABSetupItemBearerSURes) *int64 {
	return &v.extCount
}
func BridgeERABSetupItemBearerSUResFieldExtData(v *ERABSetupItemBearerSURes) *[][]byte {
	return &v.extData
}
func BridgeERABSetupItemBearerSUResFieldExtOrigin(v *ERABSetupItemBearerSURes) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABSetupItemBearerSUResFieldExtPresent(v *ERABSetupItemBearerSURes) *[]bool {
	return &v.extPresent
}
func BridgeERABSetupItemBearerSUResFieldExtWire(v *ERABSetupItemBearerSURes) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABSetupItemBearerSUResFieldIEExtensionsIndef(v *ERABSetupItemBearerSURes) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABSetupItemBearerSUResFieldPerExtPadding(v *ERABSetupItemBearerSURes) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABSetupItemBearerSUResFieldPerPadding(v *ERABSetupItemBearerSURes) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSetupItemBearerSUResFieldReceived(v *ERABSetupItemBearerSURes) *bool {
	return &v.received
}
func BridgeERABSetupItemBearerSUResFieldReceivedAbsolute(v *ERABSetupItemBearerSURes) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupItemBearerSUResFieldReceivedBytes(v *ERABSetupItemBearerSURes) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupItemBearerSUResFieldReceivedLocation(v *ERABSetupItemBearerSURes) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupItemBearerSUResFieldReplay(v *ERABSetupItemBearerSURes) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResFieldStream(v *ERABSetupItemBearerSURes) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupItemBearerSUResFieldWithoutReplay(v *ERABSetupItemBearerSURes) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEContainerAPERValueFieldContext(v *ERABSetupItemBearerSUResIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEContainerAPERValueFieldReceived(v *ERABSetupItemBearerSUResIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEContainerAPERValueFieldReplay(v *ERABSetupItemBearerSUResIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEContainerAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCapture(v *ERABSetupItemBearerSUResIEContainerValueCodec) *func(ERABSetupItemBearerSUResIEContainer, aper.DecodeState) (ERABSetupItemBearerSUResIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldCompare(v *ERABSetupItemBearerSUResIEContainerValueCodec) *func(ERABSetupItemBearerSUResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldContext(v *ERABSetupItemBearerSUResIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldDecode(v *ERABSetupItemBearerSUResIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEContainer, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldEncode(v *ERABSetupItemBearerSUResIEContainerValueCodec) *func(ERABSetupItemBearerSUResIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecFieldPath(v *ERABSetupItemBearerSUResIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResIEContainerValueCodec, a0 ERABSetupItemBearerSUResIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResIEContainerValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResIEContainerValueCodec, a0 ERABSetupItemBearerSUResIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResIEFieldAPERValueFieldContext(v *ERABSetupItemBearerSUResIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEFieldAPERValueFieldReceived(v *ERABSetupItemBearerSUResIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEFieldAPERValueFieldReplay(v *ERABSetupItemBearerSUResIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEFieldAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEFieldFieldReceived(v *ERABSetupItemBearerSUResIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEFieldFieldReplay(v *ERABSetupItemBearerSUResIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEFieldFieldStream(v *ERABSetupItemBearerSUResIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupItemBearerSUResIEFieldFieldWithoutReplay(v *ERABSetupItemBearerSUResIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEFieldMethodMarshalAPERTo(v *ERABSetupItemBearerSUResIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemBearerSUResIEFieldMethodUnmarshalAPERFrom(v *ERABSetupItemBearerSUResIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCapture(v *ERABSetupItemBearerSUResIEFieldValueCodec) *func(ERABSetupItemBearerSUResIEField, aper.DecodeState) (ERABSetupItemBearerSUResIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldCompare(v *ERABSetupItemBearerSUResIEFieldValueCodec) *func(ERABSetupItemBearerSUResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldContext(v *ERABSetupItemBearerSUResIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldDecode(v *ERABSetupItemBearerSUResIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEField, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldEncode(v *ERABSetupItemBearerSUResIEFieldValueCodec) *func(ERABSetupItemBearerSUResIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecFieldPath(v *ERABSetupItemBearerSUResIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResIEFieldValueCodec, a0 ERABSetupItemBearerSUResIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResIEFieldValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResIEFieldValueCodec, a0 ERABSetupItemBearerSUResIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResIETableMethodInfoERABSetupItemBearerSURes(v ERABSetupItemBearerSUResIETable) s00.FieldInfo {
	return v.infoERABSetupItemBearerSURes()
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListAPERValueFieldContext(v *ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListAPERValueFieldReceived(v *ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListAPERValueFieldReplay(v *ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCapture(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldCompare(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldContext(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldDecode(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldEncode(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecFieldPath(v *ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResIEValueERABIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResIEValueFieldId(v *ERABSetupItemBearerSUResIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABSetupItemBearerSUResIEValueFieldIsOpaque(v *ERABSetupItemBearerSUResIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABSetupItemBearerSUResIEValueFieldOpaque(v *ERABSetupItemBearerSUResIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABSetupItemBearerSUResIEValueFieldReceived(v *ERABSetupItemBearerSUResIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEValueFieldReplay(v *ERABSetupItemBearerSUResIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEValueFieldRowERABSetupItemBearerSURes(v *ERABSetupItemBearerSUResIEValue) **ERABSetupItemBearerSURes {
	return &v.rowERABSetupItemBearerSURes
}
func BridgeERABSetupItemBearerSUResIEValueMethodCaptureSemantics(v ERABSetupItemBearerSUResIEValue, a0 aper.SemanticCapture) ERABSetupItemBearerSUResIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABSetupItemBearerSUResIEValueMethodCompareSemantics(v ERABSetupItemBearerSUResIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABSetupItemBearerSUResIEValueMethodDecode(v ERABSetupItemBearerSUResIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABSetupItemBearerSUResIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABSetupItemBearerSUResIEValueMethodEncode(v ERABSetupItemBearerSUResIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABSetupItemBearerSUResIEValueMethodEncodeFresh(v ERABSetupItemBearerSUResIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABSetupItemBearerSUResIEValueMethodMatchesID(v ERABSetupItemBearerSUResIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABSetupItemBearerSUResIEValueMethodReason(v ERABSetupItemBearerSUResIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABSetupItemBearerSUResIEValueMethodRule(v ERABSetupItemBearerSUResIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSUResIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemBearerSUResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResIEValueProtocolIEContainerListValueCodec, a0 ERABSetupItemBearerSUResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERBudget(v *ERABSetupItemBearerSURes, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERBudgetValue(v *ERABSetupItemBearerSURes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERChanged(v *ERABSetupItemBearerSURes, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERChangedValue(v *ERABSetupItemBearerSURes, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERLegacy(v *ERABSetupItemBearerSURes) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERNewValue(v *ERABSetupItemBearerSURes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERPlanned(v *ERABSetupItemBearerSURes, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResMethodMarshalAPERTo(v *ERABSetupItemBearerSURes, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemBearerSUResMethodUnmarshalAPERFrom(v *ERABSetupItemBearerSURes, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemBearerSUResMethodUnmarshalAPERLegacy(v *ERABSetupItemBearerSURes, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupItemBearerSUResMethodUnmarshalAPERWithOptions(v *ERABSetupItemBearerSURes, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupItemBearerSUResValueCodecFieldCapture(v *ERABSetupItemBearerSUResValueCodec) *func(ERABSetupItemBearerSURes, aper.DecodeState) (ERABSetupItemBearerSURes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemBearerSUResValueCodecFieldCompare(v *ERABSetupItemBearerSUResValueCodec) *func(ERABSetupItemBearerSURes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemBearerSUResValueCodecFieldContext(v *ERABSetupItemBearerSUResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemBearerSUResValueCodecFieldDecode(v *ERABSetupItemBearerSUResValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemBearerSURes, error) {
	return &v.decode
}
func BridgeERABSetupItemBearerSUResValueCodecFieldEncode(v *ERABSetupItemBearerSUResValueCodec) *func(ERABSetupItemBearerSURes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemBearerSUResValueCodecFieldPath(v *ERABSetupItemBearerSUResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemBearerSUResValueCodecMethodEncodeBudgetValue(v ERABSetupItemBearerSUResValueCodec, a0 ERABSetupItemBearerSURes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemBearerSUResValueCodecMethodEncodeChanged(v ERABSetupItemBearerSUResValueCodec, a0 ERABSetupItemBearerSURes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResAPERValueFieldContext(v *ERABSetupItemCtxtSUResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResAPERValueFieldReceived(v *ERABSetupItemCtxtSUResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResAPERValueFieldReplay(v *ERABSetupItemCtxtSUResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldCodec(v *ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) *ERABSetupItemCtxtSUResValueCodec {
	return &v.codec
}
func BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldGet(v *ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) *func(*ERABSetupItemCtxtSUResIEValue) (*ERABSetupItemCtxtSURes, bool) {
	return &v.get
}
func BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldInfo(v *ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBindingFieldInject(v *ERABSetupItemCtxtSUResERABSetupItemCtxtSUResIEBinding) *func(ERABSetupItemCtxtSURes) ERABSetupItemCtxtSUResIEValue {
	return &v.inject
}
func BridgeERABSetupItemCtxtSUResFieldExtCount(v *ERABSetupItemCtxtSURes) *int64   { return &v.extCount }
func BridgeERABSetupItemCtxtSUResFieldExtData(v *ERABSetupItemCtxtSURes) *[][]byte { return &v.extData }
func BridgeERABSetupItemCtxtSUResFieldExtOrigin(v *ERABSetupItemCtxtSURes) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABSetupItemCtxtSUResFieldExtPresent(v *ERABSetupItemCtxtSURes) *[]bool {
	return &v.extPresent
}
func BridgeERABSetupItemCtxtSUResFieldExtWire(v *ERABSetupItemCtxtSURes) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABSetupItemCtxtSUResFieldIEExtensionsIndef(v *ERABSetupItemCtxtSURes) *bool {
	return &v.iEExtensionsIndef
}
func BridgeERABSetupItemCtxtSUResFieldPerExtPadding(v *ERABSetupItemCtxtSURes) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABSetupItemCtxtSUResFieldPerPadding(v *ERABSetupItemCtxtSURes) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSetupItemCtxtSUResFieldReceived(v *ERABSetupItemCtxtSURes) *bool { return &v.received }
func BridgeERABSetupItemCtxtSUResFieldReceivedAbsolute(v *ERABSetupItemCtxtSURes) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupItemCtxtSUResFieldReceivedBytes(v *ERABSetupItemCtxtSURes) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupItemCtxtSUResFieldReceivedLocation(v *ERABSetupItemCtxtSURes) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupItemCtxtSUResFieldReplay(v *ERABSetupItemCtxtSURes) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResFieldStream(v *ERABSetupItemCtxtSURes) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupItemCtxtSUResFieldWithoutReplay(v *ERABSetupItemCtxtSURes) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEContainerAPERValueFieldContext(v *ERABSetupItemCtxtSUResIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEContainerAPERValueFieldReceived(v *ERABSetupItemCtxtSUResIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEContainerAPERValueFieldReplay(v *ERABSetupItemCtxtSUResIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEContainerAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCapture(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *func(ERABSetupItemCtxtSUResIEContainer, aper.DecodeState) (ERABSetupItemCtxtSUResIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldCompare(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *func(ERABSetupItemCtxtSUResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldContext(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldDecode(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEContainer, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldEncode(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *func(ERABSetupItemCtxtSUResIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecFieldPath(v *ERABSetupItemCtxtSUResIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResIEContainerValueCodec, a0 ERABSetupItemCtxtSUResIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResIEContainerValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResIEContainerValueCodec, a0 ERABSetupItemCtxtSUResIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResIEFieldAPERValueFieldContext(v *ERABSetupItemCtxtSUResIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEFieldAPERValueFieldReceived(v *ERABSetupItemCtxtSUResIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEFieldAPERValueFieldReplay(v *ERABSetupItemCtxtSUResIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEFieldAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEFieldFieldReceived(v *ERABSetupItemCtxtSUResIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEFieldFieldReplay(v *ERABSetupItemCtxtSUResIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEFieldFieldStream(v *ERABSetupItemCtxtSUResIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABSetupItemCtxtSUResIEFieldFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEFieldMethodMarshalAPERTo(v *ERABSetupItemCtxtSUResIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemCtxtSUResIEFieldMethodUnmarshalAPERFrom(v *ERABSetupItemCtxtSUResIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCapture(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *func(ERABSetupItemCtxtSUResIEField, aper.DecodeState) (ERABSetupItemCtxtSUResIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldCompare(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *func(ERABSetupItemCtxtSUResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldContext(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldDecode(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEField, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldEncode(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *func(ERABSetupItemCtxtSUResIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecFieldPath(v *ERABSetupItemCtxtSUResIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResIEFieldValueCodec, a0 ERABSetupItemCtxtSUResIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResIEFieldValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResIEFieldValueCodec, a0 ERABSetupItemCtxtSUResIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResIETableMethodInfoERABSetupItemCtxtSURes(v ERABSetupItemCtxtSUResIETable) s00.FieldInfo {
	return v.infoERABSetupItemCtxtSURes()
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValueFieldContext(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValueFieldReceived(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValueFieldReplay(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCapture(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldCompare(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldContext(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldDecode(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldEncode(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecFieldPath(v *ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResIEValueERABIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResIEValueFieldId(v *ERABSetupItemCtxtSUResIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABSetupItemCtxtSUResIEValueFieldIsOpaque(v *ERABSetupItemCtxtSUResIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABSetupItemCtxtSUResIEValueFieldOpaque(v *ERABSetupItemCtxtSUResIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABSetupItemCtxtSUResIEValueFieldReceived(v *ERABSetupItemCtxtSUResIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEValueFieldReplay(v *ERABSetupItemCtxtSUResIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEValueFieldRowERABSetupItemCtxtSURes(v *ERABSetupItemCtxtSUResIEValue) **ERABSetupItemCtxtSURes {
	return &v.rowERABSetupItemCtxtSURes
}
func BridgeERABSetupItemCtxtSUResIEValueMethodCaptureSemantics(v ERABSetupItemCtxtSUResIEValue, a0 aper.SemanticCapture) ERABSetupItemCtxtSUResIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodCompareSemantics(v ERABSetupItemCtxtSUResIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodDecode(v ERABSetupItemCtxtSUResIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABSetupItemCtxtSUResIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodEncode(v ERABSetupItemCtxtSUResIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABSetupItemCtxtSUResIEValueMethodEncodeFresh(v ERABSetupItemCtxtSUResIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodMatchesID(v ERABSetupItemCtxtSUResIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodReason(v ERABSetupItemCtxtSUResIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABSetupItemCtxtSUResIEValueMethodRule(v ERABSetupItemCtxtSUResIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *func(ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResIEValueProtocolIEContainerListValueCodec, a0 ERABSetupItemCtxtSUResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERBudget(v *ERABSetupItemCtxtSURes, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERBudgetValue(v *ERABSetupItemCtxtSURes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERChanged(v *ERABSetupItemCtxtSURes, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERChangedValue(v *ERABSetupItemCtxtSURes, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERLegacy(v *ERABSetupItemCtxtSURes) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERNewValue(v *ERABSetupItemCtxtSURes, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERPlanned(v *ERABSetupItemCtxtSURes, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResMethodMarshalAPERTo(v *ERABSetupItemCtxtSURes, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupItemCtxtSUResMethodUnmarshalAPERFrom(v *ERABSetupItemCtxtSURes, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupItemCtxtSUResMethodUnmarshalAPERLegacy(v *ERABSetupItemCtxtSURes, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupItemCtxtSUResMethodUnmarshalAPERWithOptions(v *ERABSetupItemCtxtSURes, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldCapture(v *ERABSetupItemCtxtSUResValueCodec) *func(ERABSetupItemCtxtSURes, aper.DecodeState) (ERABSetupItemCtxtSURes, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldCompare(v *ERABSetupItemCtxtSUResValueCodec) *func(ERABSetupItemCtxtSURes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldContext(v *ERABSetupItemCtxtSUResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldDecode(v *ERABSetupItemCtxtSUResValueCodec) *func([]byte, aper.DecodeState) (ERABSetupItemCtxtSURes, error) {
	return &v.decode
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldEncode(v *ERABSetupItemCtxtSUResValueCodec) *func(ERABSetupItemCtxtSURes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupItemCtxtSUResValueCodecFieldPath(v *ERABSetupItemCtxtSUResValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupItemCtxtSUResValueCodecMethodEncodeBudgetValue(v ERABSetupItemCtxtSUResValueCodec, a0 ERABSetupItemCtxtSURes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupItemCtxtSUResValueCodecMethodEncodeChanged(v ERABSetupItemCtxtSUResValueCodec, a0 ERABSetupItemCtxtSURes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupListBearerSUResAPERValueFieldContext(v *ERABSetupListBearerSUResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupListBearerSUResAPERValueFieldReceived(v *ERABSetupListBearerSUResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupListBearerSUResAPERValueFieldReplay(v *ERABSetupListBearerSUResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupListBearerSUResAPERValueFieldWithoutReplay(v *ERABSetupListBearerSUResAPERValue) *bool {
	return &v.withoutReplay
}
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
func BridgeERABSetupListBearerSUResValueCodecMethodEncodeBudgetValue(v ERABSetupListBearerSUResValueCodec, a0 ERABSetupListBearerSURes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupListBearerSUResValueCodecMethodEncodeChanged(v ERABSetupListBearerSUResValueCodec, a0 ERABSetupListBearerSURes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupListCtxtSUResAPERValueFieldContext(v *ERABSetupListCtxtSUResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupListCtxtSUResAPERValueFieldReceived(v *ERABSetupListCtxtSUResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupListCtxtSUResAPERValueFieldReplay(v *ERABSetupListCtxtSUResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupListCtxtSUResAPERValueFieldWithoutReplay(v *ERABSetupListCtxtSUResAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeERABSetupListCtxtSUResValueCodecMethodEncodeBudgetValue(v ERABSetupListCtxtSUResValueCodec, a0 ERABSetupListCtxtSURes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupListCtxtSUResValueCodecMethodEncodeChanged(v ERABSetupListCtxtSUResValueCodec, a0 ERABSetupListCtxtSURes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSubjecttoDataForwardingListAPERValueFieldContext(v *ERABSubjecttoDataForwardingListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSubjecttoDataForwardingListAPERValueFieldReceived(v *ERABSubjecttoDataForwardingListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSubjecttoDataForwardingListAPERValueFieldReplay(v *ERABSubjecttoDataForwardingListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSubjecttoDataForwardingListAPERValueFieldWithoutReplay(v *ERABSubjecttoDataForwardingListAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeERABSubjecttoDataForwardingListValueCodecMethodEncodeBudgetValue(v ERABSubjecttoDataForwardingListValueCodec, a0 ERABSubjecttoDataForwardingList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSubjecttoDataForwardingListValueCodecMethodEncodeChanged(v ERABSubjecttoDataForwardingListValueCodec, a0 ERABSubjecttoDataForwardingList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
