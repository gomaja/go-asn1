// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s19 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s19

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// NASNonDeliveryIndicationIEContainer is the concrete ProtocolIEContainer[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEContainer []NASNonDeliveryIndicationIEField

// NASNonDeliveryIndicationIEField is the concrete ProtocolIEField[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         NASNonDeliveryIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEField) WithoutReplay() NASNonDeliveryIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *NASNonDeliveryIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *NASNonDeliveryIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *NASNonDeliveryIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASNonDeliveryIndicationIEField{}
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
	var zero NASNonDeliveryIndicationIEValue

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

// M3ConfigurationValueCodec is the concrete ValueCodec[M3Configuration].
type M3ConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M3Configuration,

		error)
	encode func(M3Configuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M3Configuration, aper.DecodeState,

	) (M3Configuration, aper.Snapshot,

	)
	compare func(M3Configuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M3ConfigurationValueCodec) New(value M3Configuration,

) (M3ConfigurationAPERValue, error) {
	if c.encode == nil {
		return M3ConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M3ConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M3ConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M3ConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M3ConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M3ConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M3ConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M3ConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M3ConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M3ConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M3ConfigurationValueCodec) EncodeAPER(value M3ConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M3ConfigurationValueCodec) encodeBudgetValue(value M3Configuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M3ConfigurationValueCodec) encodeChanged(value M3Configuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M4ConfigurationValueCodec is the concrete ValueCodec[M4Configuration].
type M4ConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M4Configuration,

		error)
	encode func(M4Configuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M4Configuration, aper.DecodeState,

	) (M4Configuration, aper.Snapshot,

	)
	compare func(M4Configuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M4ConfigurationValueCodec) New(value M4Configuration,

) (M4ConfigurationAPERValue, error) {
	if c.encode == nil {
		return M4ConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4ConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M4ConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M4ConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M4ConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M4ConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M4ConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M4ConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M4ConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M4ConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M4ConfigurationValueCodec) EncodeAPER(value M4ConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M4ConfigurationValueCodec) encodeBudgetValue(value M4Configuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M4ConfigurationValueCodec) encodeChanged(value M4Configuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M5ConfigurationValueCodec is the concrete ValueCodec[M5Configuration].
type M5ConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M5Configuration,

		error)
	encode func(M5Configuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M5Configuration, aper.DecodeState,

	) (M5Configuration, aper.Snapshot,

	)
	compare func(M5Configuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M5ConfigurationValueCodec) New(value M5Configuration,

) (M5ConfigurationAPERValue, error) {
	if c.encode == nil {
		return M5ConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5ConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M5ConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M5ConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M5ConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M5ConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M5ConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M5ConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M5ConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M5ConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M5ConfigurationValueCodec) EncodeAPER(value M5ConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M5ConfigurationValueCodec) encodeBudgetValue(value M5Configuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M5ConfigurationValueCodec) encodeChanged(value M5Configuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6ConfigurationValueCodec is the concrete ValueCodec[M6Configuration].
type M6ConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M6Configuration,

		error)
	encode func(M6Configuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M6Configuration, aper.DecodeState,

	) (M6Configuration, aper.Snapshot,

	)
	compare func(M6Configuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6ConfigurationValueCodec) New(value M6Configuration,

) (M6ConfigurationAPERValue, error) {
	if c.encode == nil {
		return M6ConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6ConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6ConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6ConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6ConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6ConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6ConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6ConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6ConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6ConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6ConfigurationValueCodec) EncodeAPER(value M6ConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M6ConfigurationValueCodec) encodeBudgetValue(value M6Configuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6ConfigurationValueCodec) encodeChanged(value M6Configuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M7ConfigurationValueCodec is the concrete ValueCodec[M7Configuration].
type M7ConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M7Configuration,

		error)
	encode func(M7Configuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M7Configuration, aper.DecodeState,

	) (M7Configuration, aper.Snapshot,

	)
	compare func(M7Configuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M7ConfigurationValueCodec) New(value M7Configuration,

) (M7ConfigurationAPERValue, error) {
	if c.encode == nil {
		return M7ConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7ConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M7ConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M7ConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M7ConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M7ConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M7ConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M7ConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M7ConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M7ConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M7ConfigurationValueCodec) EncodeAPER(value M7ConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M7ConfigurationValueCodec) encodeBudgetValue(value M7Configuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M7ConfigurationValueCodec) encodeChanged(value M7Configuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggedMDTTriggerValueCodec is the concrete ValueCodec[LoggedMDTTrigger].
type LoggedMDTTriggerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMDTTrigger,

		error)
	encode func(LoggedMDTTrigger,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMDTTrigger, aper.DecodeState,

	) (LoggedMDTTrigger, aper.Snapshot,

	)
	compare func(LoggedMDTTrigger, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMDTTriggerValueCodec) New(value LoggedMDTTrigger,

) (LoggedMDTTriggerAPERValue, error) {
	if c.encode == nil {
		return LoggedMDTTriggerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMDTTriggerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMDTTriggerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMDTTriggerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMDTTriggerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMDTTriggerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMDTTriggerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMDTTriggerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMDTTriggerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMDTTriggerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMDTTriggerValueCodec) EncodeAPER(value LoggedMDTTriggerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMDTTriggerValueCodec) encodeBudgetValue(value LoggedMDTTrigger,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMDTTriggerValueCodec) encodeChanged(value LoggedMDTTrigger,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MutingPatternInformationValueCodec is the concrete ValueCodec[MutingPatternInformation].
type MutingPatternInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MutingPatternInformation,

		error)
	encode func(MutingPatternInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MutingPatternInformation, aper.DecodeState,

	) (MutingPatternInformation, aper.Snapshot,

	)
	compare func(MutingPatternInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MutingPatternInformationValueCodec) New(value MutingPatternInformation,

) (MutingPatternInformationAPERValue, error) {
	if c.encode == nil {
		return MutingPatternInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MutingPatternInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MutingPatternInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MutingPatternInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MutingPatternInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MutingPatternInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MutingPatternInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MutingPatternInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MutingPatternInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MutingPatternInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MutingPatternInformationValueCodec) EncodeAPER(value MutingPatternInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MutingPatternInformationValueCodec) encodeBudgetValue(value MutingPatternInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MutingPatternInformationValueCodec) encodeChanged(value MutingPatternInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ContextatSourceValueCodec is the concrete ValueCodec[ContextatSource].
type ContextatSourceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ContextatSource,

		error)
	encode func(ContextatSource,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ContextatSource, aper.DecodeState,

	) (ContextatSource, aper.Snapshot,

	)
	compare func(ContextatSource, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ContextatSourceValueCodec) New(value ContextatSource,

) (ContextatSourceAPERValue, error) {
	if c.encode == nil {
		return ContextatSourceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ContextatSourceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ContextatSourceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ContextatSourceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ContextatSourceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ContextatSourceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ContextatSourceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ContextatSourceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ContextatSourceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ContextatSourceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ContextatSourceValueCodec) EncodeAPER(value ContextatSourceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ContextatSourceValueCodec) encodeBudgetValue(value ContextatSource,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ContextatSourceValueCodec) encodeChanged(value ContextatSource,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GlobalRANNODEIDValueCodec is the concrete ValueCodec[GlobalRANNODEID].
type GlobalRANNODEIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (GlobalRANNODEID,

		error)
	encode func(GlobalRANNODEID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(GlobalRANNODEID, aper.DecodeState,

	) (GlobalRANNODEID, aper.Snapshot,

	)
	compare func(GlobalRANNODEID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GlobalRANNODEIDValueCodec) New(value GlobalRANNODEID,

) (GlobalRANNODEIDAPERValue, error) {
	if c.encode == nil {
		return GlobalRANNODEIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GlobalRANNODEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GlobalRANNODEIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GlobalRANNODEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GlobalRANNODEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GlobalRANNODEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GlobalRANNODEIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GlobalRANNODEIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GlobalRANNODEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GlobalRANNODEIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GlobalRANNODEIDValueCodec) EncodeAPER(value GlobalRANNODEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c GlobalRANNODEIDValueCodec) encodeBudgetValue(value GlobalRANNODEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GlobalRANNODEIDValueCodec) encodeChanged(value GlobalRANNODEID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESecurityCapabilitiesValueCodec is the concrete ValueCodec[NRUESecurityCapabilities].
type NRUESecurityCapabilitiesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESecurityCapabilities,

		error)
	encode func(NRUESecurityCapabilities,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESecurityCapabilities, aper.DecodeState,

	) (NRUESecurityCapabilities, aper.Snapshot,

	)
	compare func(NRUESecurityCapabilities, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESecurityCapabilitiesValueCodec) New(value NRUESecurityCapabilities,

) (NRUESecurityCapabilitiesAPERValue, error) {
	if c.encode == nil {
		return NRUESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESecurityCapabilitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESecurityCapabilitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESecurityCapabilitiesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESecurityCapabilitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESecurityCapabilitiesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESecurityCapabilitiesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESecurityCapabilitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESecurityCapabilitiesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESecurityCapabilitiesValueCodec) EncodeAPER(value NRUESecurityCapabilitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESecurityCapabilitiesValueCodec) encodeBudgetValue(value NRUESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESecurityCapabilitiesValueCodec) encodeChanged(value NRUESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRV2XServicesAuthorizedValueCodec is the concrete ValueCodec[NRV2XServicesAuthorized].
type NRV2XServicesAuthorizedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRV2XServicesAuthorized,

		error)
	encode func(NRV2XServicesAuthorized,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRV2XServicesAuthorized, aper.DecodeState,

	) (NRV2XServicesAuthorized, aper.Snapshot,

	)
	compare func(NRV2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRV2XServicesAuthorizedValueCodec) New(value NRV2XServicesAuthorized,

) (NRV2XServicesAuthorizedAPERValue, error) {
	if c.encode == nil {
		return NRV2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRV2XServicesAuthorizedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRV2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRV2XServicesAuthorizedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRV2XServicesAuthorizedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRV2XServicesAuthorizedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRV2XServicesAuthorizedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRV2XServicesAuthorizedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRV2XServicesAuthorizedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRV2XServicesAuthorizedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRV2XServicesAuthorizedValueCodec) EncodeAPER(value NRV2XServicesAuthorizedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRV2XServicesAuthorizedValueCodec) encodeBudgetValue(value NRV2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRV2XServicesAuthorizedValueCodec) encodeChanged(value NRV2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRUESidelinkAggregateMaximumBitrateValueCodec is the concrete ValueCodec[NRUESidelinkAggregateMaximumBitrate].
type NRUESidelinkAggregateMaximumBitrateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrate,

		error)
	encode func(NRUESidelinkAggregateMaximumBitrate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRUESidelinkAggregateMaximumBitrate, aper.DecodeState,

	) (NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,

	)
	compare func(NRUESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRUESidelinkAggregateMaximumBitrateValueCodec) New(value NRUESidelinkAggregateMaximumBitrate,

) (NRUESidelinkAggregateMaximumBitrateAPERValue, error) {
	if c.encode == nil {
		return NRUESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRUESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRUESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRUESidelinkAggregateMaximumBitrateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRUESidelinkAggregateMaximumBitrateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRUESidelinkAggregateMaximumBitrateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRUESidelinkAggregateMaximumBitrateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRUESidelinkAggregateMaximumBitrateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRUESidelinkAggregateMaximumBitrateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRUESidelinkAggregateMaximumBitrateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRUESidelinkAggregateMaximumBitrateValueCodec) EncodeAPER(value NRUESidelinkAggregateMaximumBitrateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRUESidelinkAggregateMaximumBitrateValueCodec) encodeBudgetValue(value NRUESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRUESidelinkAggregateMaximumBitrateValueCodec) encodeChanged(value NRUESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) NASNonDeliveryIndicationIEValue

	get func(*NASNonDeliveryIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b NASNonDeliveryIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (NASNonDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASNonDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASNonDeliveryIndicationMMEUES1APIDIEBinding) Get(field *NASNonDeliveryIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASNonDeliveryIndicationENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) NASNonDeliveryIndicationIEValue

	get func(*NASNonDeliveryIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b NASNonDeliveryIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (NASNonDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASNonDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASNonDeliveryIndicationENBUES1APIDIEBinding) Get(field *NASNonDeliveryIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASNonDeliveryIndicationNASPDUIEBinding is the concrete IEBinding[NASPDU, NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationNASPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASPDUValueCodec
	inject func(s00.NASPDU,

	) NASNonDeliveryIndicationIEValue

	get func(*NASNonDeliveryIndicationIEValue,

	) (*s00.NASPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationNASPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationNASPDUIEBinding) Codec() s01.NASPDUValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b NASNonDeliveryIndicationNASPDUIEBinding) New(value s00.NASPDU,

) (NASNonDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASNonDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASNonDeliveryIndicationNASPDUIEBinding) Get(field *NASNonDeliveryIndicationIEField) (*s00.NASPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASNonDeliveryIndicationCauseIEBinding is the concrete IEBinding[Cause, NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) NASNonDeliveryIndicationIEValue

	get func(*NASNonDeliveryIndicationIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b NASNonDeliveryIndicationCauseIEBinding) New(value s14.Cause,

) (NASNonDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASNonDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Get(field *NASNonDeliveryIndicationIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OverloadResponseValueCodec is the concrete ValueCodec[OverloadResponse].
type OverloadResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (OverloadResponse,

		error)
	encode func(OverloadResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(OverloadResponse, aper.DecodeState,

	) (OverloadResponse, aper.Snapshot,

	)
	compare func(OverloadResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadResponseValueCodec) New(value OverloadResponse,

) (OverloadResponseAPERValue, error) {
	if c.encode == nil {
		return OverloadResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadResponseValueCodec) EncodeAPER(value OverloadResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c OverloadResponseValueCodec) encodeBudgetValue(value OverloadResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadResponseValueCodec) encodeChanged(value OverloadResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingEDRXInformationValueCodec is the concrete ValueCodec[NBIoTPagingEDRXInformation].
type NBIoTPagingEDRXInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformation,

		error)
	encode func(NBIoTPagingEDRXInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NBIoTPagingEDRXInformation, aper.DecodeState,

	) (NBIoTPagingEDRXInformation, aper.Snapshot,

	)
	compare func(NBIoTPagingEDRXInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingEDRXInformationValueCodec) New(value NBIoTPagingEDRXInformation,

) (NBIoTPagingEDRXInformationAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingEDRXInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingEDRXInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingEDRXInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingEDRXInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingEDRXInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingEDRXInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingEDRXInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingEDRXInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingEDRXInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingEDRXInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingEDRXInformationValueCodec) EncodeAPER(value NBIoTPagingEDRXInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NBIoTPagingEDRXInformationValueCodec) encodeBudgetValue(value NBIoTPagingEDRXInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingEDRXInformationValueCodec) encodeChanged(value NBIoTPagingEDRXInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventL1LoggedMDTConfigValueCodec is the concrete ValueCodec[EventL1LoggedMDTConfig].
type EventL1LoggedMDTConfigValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventL1LoggedMDTConfig,

		error)
	encode func(EventL1LoggedMDTConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventL1LoggedMDTConfig, aper.DecodeState,

	) (EventL1LoggedMDTConfig, aper.Snapshot,

	)
	compare func(EventL1LoggedMDTConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventL1LoggedMDTConfigValueCodec) New(value EventL1LoggedMDTConfig,

) (EventL1LoggedMDTConfigAPERValue, error) {
	if c.encode == nil {
		return EventL1LoggedMDTConfigAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventL1LoggedMDTConfigAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventL1LoggedMDTConfigAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventL1LoggedMDTConfigAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventL1LoggedMDTConfigValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventL1LoggedMDTConfigAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventL1LoggedMDTConfigAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventL1LoggedMDTConfigAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventL1LoggedMDTConfigAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventL1LoggedMDTConfigAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventL1LoggedMDTConfigValueCodec) EncodeAPER(value EventL1LoggedMDTConfigAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EventL1LoggedMDTConfigValueCodec) encodeBudgetValue(value EventL1LoggedMDTConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventL1LoggedMDTConfigValueCodec) encodeChanged(value EventL1LoggedMDTConfig,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EventTriggerValueCodec is the concrete ValueCodec[EventTrigger].
type EventTriggerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EventTrigger,

		error)
	encode func(EventTrigger,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EventTrigger, aper.DecodeState,

	) (EventTrigger, aper.Snapshot,

	)
	compare func(EventTrigger, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EventTriggerValueCodec) New(value EventTrigger,

) (EventTriggerAPERValue, error) {
	if c.encode == nil {
		return EventTriggerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EventTriggerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EventTriggerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EventTriggerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EventTriggerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EventTriggerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EventTriggerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EventTriggerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EventTriggerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EventTriggerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EventTriggerValueCodec) EncodeAPER(value EventTriggerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EventTriggerValueCodec) encodeBudgetValue(value EventTrigger,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EventTriggerValueCodec) encodeChanged(value EventTrigger,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1ThresholdEventA2ValueCodec is the concrete ValueCodec[M1ThresholdEventA2].
type M1ThresholdEventA2ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1ThresholdEventA2,

		error)
	encode func(M1ThresholdEventA2,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1ThresholdEventA2, aper.DecodeState,

	) (M1ThresholdEventA2, aper.Snapshot,

	)
	compare func(M1ThresholdEventA2, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1ThresholdEventA2ValueCodec) New(value M1ThresholdEventA2,

) (M1ThresholdEventA2APERValue, error) {
	if c.encode == nil {
		return M1ThresholdEventA2APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1ThresholdEventA2APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1ThresholdEventA2APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1ThresholdEventA2APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1ThresholdEventA2ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1ThresholdEventA2APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1ThresholdEventA2APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1ThresholdEventA2APERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1ThresholdEventA2APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1ThresholdEventA2APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1ThresholdEventA2ValueCodec) EncodeAPER(value M1ThresholdEventA2APERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1ThresholdEventA2ValueCodec) encodeBudgetValue(value M1ThresholdEventA2,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1ThresholdEventA2ValueCodec) encodeChanged(value M1ThresholdEventA2,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MBSFNResultToLogValueCodec is the concrete ValueCodec[MBSFNResultToLog].
type MBSFNResultToLogValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MBSFNResultToLog,

		error)
	encode func(MBSFNResultToLog,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MBSFNResultToLog, aper.DecodeState,

	) (MBSFNResultToLog, aper.Snapshot,

	)
	compare func(MBSFNResultToLog, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MBSFNResultToLogValueCodec) New(value MBSFNResultToLog,

) (MBSFNResultToLogAPERValue, error) {
	if c.encode == nil {
		return MBSFNResultToLogAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNResultToLogAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNResultToLogAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MBSFNResultToLogAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MBSFNResultToLogValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNResultToLogAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MBSFNResultToLogAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MBSFNResultToLogAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MBSFNResultToLogAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MBSFNResultToLogAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MBSFNResultToLogValueCodec) EncodeAPER(value MBSFNResultToLogAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MBSFNResultToLogValueCodec) encodeBudgetValue(value MBSFNResultToLog,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MBSFNResultToLogValueCodec) encodeChanged(value MBSFNResultToLog,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MBSFNResultToLogInfoValueCodec is the concrete ValueCodec[MBSFNResultToLogInfo].
type MBSFNResultToLogInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MBSFNResultToLogInfo,

		error)
	encode func(MBSFNResultToLogInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MBSFNResultToLogInfo, aper.DecodeState,

	) (MBSFNResultToLogInfo, aper.Snapshot,

	)
	compare func(MBSFNResultToLogInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MBSFNResultToLogInfoValueCodec) New(value MBSFNResultToLogInfo,

) (MBSFNResultToLogInfoAPERValue, error) {
	if c.encode == nil {
		return MBSFNResultToLogInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MBSFNResultToLogInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MBSFNResultToLogInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MBSFNResultToLogInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MBSFNResultToLogInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MBSFNResultToLogInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MBSFNResultToLogInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MBSFNResultToLogInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MBSFNResultToLogInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MBSFNResultToLogInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MBSFNResultToLogInfoValueCodec) EncodeAPER(value MBSFNResultToLogInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MBSFNResultToLogInfoValueCodec) encodeBudgetValue(value MBSFNResultToLogInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MBSFNResultToLogInfoValueCodec) encodeChanged(value MBSFNResultToLogInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionValueCodec is the concrete ValueCodec[MDTModeExtension].
type MDTModeExtensionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtension,

		error)
	encode func(MDTModeExtension,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtension, aper.DecodeState,

	) (MDTModeExtension, aper.Snapshot,

	)
	compare func(MDTModeExtension, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionValueCodec) New(value MDTModeExtension,

) (MDTModeExtensionAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionValueCodec) EncodeAPER(value MDTModeExtensionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionValueCodec) encodeBudgetValue(value MDTModeExtension,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionValueCodec) encodeChanged(value MDTModeExtension,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECPRelocationIndicationValueCodec is the concrete ValueCodec[MMECPRelocationIndication].
type MMECPRelocationIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMECPRelocationIndication,

		error)
	encode func(MMECPRelocationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMECPRelocationIndication, aper.DecodeState,

	) (MMECPRelocationIndication, aper.Snapshot,

	)
	compare func(MMECPRelocationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECPRelocationIndicationValueCodec) New(value MMECPRelocationIndication,

) (MMECPRelocationIndicationAPERValue, error) {
	if c.encode == nil {
		return MMECPRelocationIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECPRelocationIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECPRelocationIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECPRelocationIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECPRelocationIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECPRelocationIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECPRelocationIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECPRelocationIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECPRelocationIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECPRelocationIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECPRelocationIndicationValueCodec) EncodeAPER(value MMECPRelocationIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMECPRelocationIndicationValueCodec) encodeBudgetValue(value MMECPRelocationIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECPRelocationIndicationValueCodec) encodeChanged(value MMECPRelocationIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdA2ValueCodec is the concrete ValueCodec[MeasurementThresholdA2].
type MeasurementThresholdA2ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdA2,

		error)
	encode func(MeasurementThresholdA2,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdA2, aper.DecodeState,

	) (MeasurementThresholdA2, aper.Snapshot,

	)
	compare func(MeasurementThresholdA2, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdA2ValueCodec) New(value MeasurementThresholdA2,

) (MeasurementThresholdA2APERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdA2APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdA2APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdA2APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdA2APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdA2ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdA2APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdA2APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdA2APERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdA2APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdA2APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdA2ValueCodec) EncodeAPER(value MeasurementThresholdA2APERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdA2ValueCodec) encodeBudgetValue(value MeasurementThresholdA2,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdA2ValueCodec) encodeChanged(value MeasurementThresholdA2,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementThresholdL1LoggedMDTValueCodec is the concrete ValueCodec[MeasurementThresholdL1LoggedMDT].
type MeasurementThresholdL1LoggedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDT,

		error)
	encode func(MeasurementThresholdL1LoggedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MeasurementThresholdL1LoggedMDT, aper.DecodeState,

	) (MeasurementThresholdL1LoggedMDT, aper.Snapshot,

	)
	compare func(MeasurementThresholdL1LoggedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementThresholdL1LoggedMDTValueCodec) New(value MeasurementThresholdL1LoggedMDT,

) (MeasurementThresholdL1LoggedMDTAPERValue, error) {
	if c.encode == nil {
		return MeasurementThresholdL1LoggedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementThresholdL1LoggedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementThresholdL1LoggedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementThresholdL1LoggedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementThresholdL1LoggedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementThresholdL1LoggedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementThresholdL1LoggedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementThresholdL1LoggedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementThresholdL1LoggedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementThresholdL1LoggedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementThresholdL1LoggedMDTValueCodec) EncodeAPER(value MeasurementThresholdL1LoggedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MeasurementThresholdL1LoggedMDTValueCodec) encodeBudgetValue(value MeasurementThresholdL1LoggedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementThresholdL1LoggedMDTValueCodec) encodeChanged(value MeasurementThresholdL1LoggedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MultiCellLoadReportingResponseValueCodec is the concrete ValueCodec[MultiCellLoadReportingResponse].
type MultiCellLoadReportingResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MultiCellLoadReportingResponse,

		error)
	encode func(MultiCellLoadReportingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MultiCellLoadReportingResponse, aper.DecodeState,

	) (MultiCellLoadReportingResponse, aper.Snapshot,

	)
	compare func(MultiCellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MultiCellLoadReportingResponseValueCodec) New(value MultiCellLoadReportingResponse,

) (MultiCellLoadReportingResponseAPERValue, error) {
	if c.encode == nil {
		return MultiCellLoadReportingResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MultiCellLoadReportingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MultiCellLoadReportingResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MultiCellLoadReportingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MultiCellLoadReportingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MultiCellLoadReportingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MultiCellLoadReportingResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MultiCellLoadReportingResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MultiCellLoadReportingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MultiCellLoadReportingResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MultiCellLoadReportingResponseValueCodec) EncodeAPER(value MultiCellLoadReportingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MultiCellLoadReportingResponseValueCodec) encodeBudgetValue(value MultiCellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MultiCellLoadReportingResponseValueCodec) encodeChanged(value MultiCellLoadReportingResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MultiCellLoadReportingResponseItemValueCodec is the concrete ValueCodec[MultiCellLoadReportingResponseItem].
type MultiCellLoadReportingResponseItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MultiCellLoadReportingResponseItem,

		error)
	encode func(MultiCellLoadReportingResponseItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MultiCellLoadReportingResponseItem, aper.DecodeState,

	) (MultiCellLoadReportingResponseItem, aper.Snapshot,

	)
	compare func(MultiCellLoadReportingResponseItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MultiCellLoadReportingResponseItemValueCodec) New(value MultiCellLoadReportingResponseItem,

) (MultiCellLoadReportingResponseItemAPERValue, error) {
	if c.encode == nil {
		return MultiCellLoadReportingResponseItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MultiCellLoadReportingResponseItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MultiCellLoadReportingResponseItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MultiCellLoadReportingResponseItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MultiCellLoadReportingResponseItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MultiCellLoadReportingResponseItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MultiCellLoadReportingResponseItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MultiCellLoadReportingResponseItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MultiCellLoadReportingResponseItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MultiCellLoadReportingResponseItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MultiCellLoadReportingResponseItemValueCodec) EncodeAPER(value MultiCellLoadReportingResponseItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MultiCellLoadReportingResponseItemValueCodec) encodeBudgetValue(value MultiCellLoadReportingResponseItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MultiCellLoadReportingResponseItemValueCodec) encodeChanged(value MultiCellLoadReportingResponseItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASDeliveryIndicationValueCodec is the concrete ValueCodec[NASDeliveryIndication].
type NASDeliveryIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASDeliveryIndication,

		error)
	encode func(NASDeliveryIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASDeliveryIndication, aper.DecodeState,

	) (NASDeliveryIndication, aper.Snapshot,

	)
	compare func(NASDeliveryIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASDeliveryIndicationValueCodec) New(value NASDeliveryIndication,

) (NASDeliveryIndicationAPERValue, error) {
	if c.encode == nil {
		return NASDeliveryIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASDeliveryIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASDeliveryIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASDeliveryIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASDeliveryIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASDeliveryIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASDeliveryIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASDeliveryIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASDeliveryIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASDeliveryIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASDeliveryIndicationValueCodec) EncodeAPER(value NASDeliveryIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASDeliveryIndicationValueCodec) encodeBudgetValue(value NASDeliveryIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASDeliveryIndicationValueCodec) encodeChanged(value NASDeliveryIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NGENBValueCodec is the concrete ValueCodec[NGENB].
type NGENBValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NGENB,

		error)
	encode func(NGENB,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NGENB, aper.DecodeState,

	) (NGENB, aper.Snapshot,

	)
	compare func(NGENB, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NGENBValueCodec) New(value NGENB,

) (NGENBAPERValue, error) {
	if c.encode == nil {
		return NGENBAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NGENBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NGENBAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NGENBAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NGENBValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NGENBAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NGENBAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NGENBAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NGENBAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NGENBAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NGENBValueCodec) EncodeAPER(value NGENBAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NGENBValueCodec) encodeBudgetValue(value NGENB,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NGENBValueCodec) encodeChanged(value NGENB,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRCGIValueCodec is the concrete ValueCodec[NRCGI].
type NRCGIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NRCGI,

		error)
	encode func(NRCGI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NRCGI, aper.DecodeState,

	) (NRCGI, aper.Snapshot,

	)
	compare func(NRCGI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRCGIValueCodec) New(value NRCGI,

) (NRCGIAPERValue, error) {
	if c.encode == nil {
		return NRCGIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRCGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCGIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRCGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRCGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRCGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRCGIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRCGIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRCGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRCGIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRCGIValueCodec) EncodeAPER(value NRCGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NRCGIValueCodec) encodeBudgetValue(value NRCGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRCGIValueCodec) encodeChanged(value NRCGI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NotificationCellListValueCodec is the concrete ValueCodec[NotificationCellList].
type NotificationCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NotificationCellList,

		error)
	encode func(NotificationCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NotificationCellList, aper.DecodeState,

	) (NotificationCellList, aper.Snapshot,

	)
	compare func(NotificationCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NotificationCellListValueCodec) New(value NotificationCellList,

) (NotificationCellListAPERValue, error) {
	if c.encode == nil {
		return NotificationCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NotificationCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NotificationCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NotificationCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NotificationCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NotificationCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NotificationCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NotificationCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NotificationCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NotificationCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NotificationCellListValueCodec) EncodeAPER(value NotificationCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NotificationCellListValueCodec) encodeBudgetValue(value NotificationCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NotificationCellListValueCodec) encodeChanged(value NotificationCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NotificationCellListItemValueCodec is the concrete ValueCodec[NotificationCellListItem].
type NotificationCellListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NotificationCellListItem,

		error)
	encode func(NotificationCellListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NotificationCellListItem, aper.DecodeState,

	) (NotificationCellListItem, aper.Snapshot,

	)
	compare func(NotificationCellListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NotificationCellListItemValueCodec) New(value NotificationCellListItem,

) (NotificationCellListItemAPERValue, error) {
	if c.encode == nil {
		return NotificationCellListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NotificationCellListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NotificationCellListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NotificationCellListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NotificationCellListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NotificationCellListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NotificationCellListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NotificationCellListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NotificationCellListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NotificationCellListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NotificationCellListItemValueCodec) EncodeAPER(value NotificationCellListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NotificationCellListItemValueCodec) encodeBudgetValue(value NotificationCellListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NotificationCellListItemValueCodec) encodeChanged(value NotificationCellListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5FlowBitRatesValueCodec is the concrete ValueCodec[PC5FlowBitRates].
type PC5FlowBitRatesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5FlowBitRates,

		error)
	encode func(PC5FlowBitRates,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5FlowBitRates, aper.DecodeState,

	) (PC5FlowBitRates, aper.Snapshot,

	)
	compare func(PC5FlowBitRates, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5FlowBitRatesValueCodec) New(value PC5FlowBitRates,

) (PC5FlowBitRatesAPERValue, error) {
	if c.encode == nil {
		return PC5FlowBitRatesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5FlowBitRatesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5FlowBitRatesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5FlowBitRatesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5FlowBitRatesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5FlowBitRatesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5FlowBitRatesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5FlowBitRatesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5FlowBitRatesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5FlowBitRatesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5FlowBitRatesValueCodec) EncodeAPER(value PC5FlowBitRatesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5FlowBitRatesValueCodec) encodeBudgetValue(value PC5FlowBitRates,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5FlowBitRatesValueCodec) encodeChanged(value PC5FlowBitRates,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M3ConfigurationAPERValue is the concrete APERValue[M3Configuration].
type M3ConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   M3Configuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M3ConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3ConfigurationAPERValue) WithoutReplay() M3ConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M4ConfigurationAPERValue is the concrete APERValue[M4Configuration].
type M4ConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   M4Configuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M4ConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ConfigurationAPERValue) WithoutReplay() M4ConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M5ConfigurationAPERValue is the concrete APERValue[M5Configuration].
type M5ConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   M5Configuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M5ConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ConfigurationAPERValue) WithoutReplay() M5ConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6ConfigurationAPERValue is the concrete APERValue[M6Configuration].
type M6ConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   M6Configuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6ConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ConfigurationAPERValue) WithoutReplay() M6ConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M7ConfigurationAPERValue is the concrete APERValue[M7Configuration].
type M7ConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   M7Configuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M7ConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ConfigurationAPERValue) WithoutReplay() M7ConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggedMDTTriggerAPERValue is the concrete APERValue[LoggedMDTTrigger].
type LoggedMDTTriggerAPERValue struct {
	context s00.BridgeCodecContext
	Value   LoggedMDTTrigger

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMDTTriggerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMDTTriggerAPERValue) WithoutReplay() LoggedMDTTriggerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MutingPatternInformationAPERValue is the concrete APERValue[MutingPatternInformation].
type MutingPatternInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   MutingPatternInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MutingPatternInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingPatternInformationAPERValue) WithoutReplay() MutingPatternInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ContextatSourceAPERValue is the concrete APERValue[ContextatSource].
type ContextatSourceAPERValue struct {
	context s00.BridgeCodecContext
	Value   ContextatSource

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ContextatSourceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ContextatSourceAPERValue) WithoutReplay() ContextatSourceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GlobalRANNODEIDAPERValue is the concrete APERValue[GlobalRANNODEID].
type GlobalRANNODEIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   GlobalRANNODEID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GlobalRANNODEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GlobalRANNODEIDAPERValue) WithoutReplay() GlobalRANNODEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESecurityCapabilitiesAPERValue is the concrete APERValue[NRUESecurityCapabilities].
type NRUESecurityCapabilitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   NRUESecurityCapabilities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESecurityCapabilitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESecurityCapabilitiesAPERValue) WithoutReplay() NRUESecurityCapabilitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRV2XServicesAuthorizedAPERValue is the concrete APERValue[NRV2XServicesAuthorized].
type NRV2XServicesAuthorizedAPERValue struct {
	context s00.BridgeCodecContext
	Value   NRV2XServicesAuthorized

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRV2XServicesAuthorizedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRV2XServicesAuthorizedAPERValue) WithoutReplay() NRV2XServicesAuthorizedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRUESidelinkAggregateMaximumBitrateAPERValue is the concrete APERValue[NRUESidelinkAggregateMaximumBitrate].
type NRUESidelinkAggregateMaximumBitrateAPERValue struct {
	context s00.BridgeCodecContext
	Value   NRUESidelinkAggregateMaximumBitrate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRUESidelinkAggregateMaximumBitrateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRUESidelinkAggregateMaximumBitrateAPERValue) WithoutReplay() NRUESidelinkAggregateMaximumBitrateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadResponseAPERValue is the concrete APERValue[OverloadResponse].
type OverloadResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   OverloadResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadResponseAPERValue) WithoutReplay() OverloadResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingEDRXInformationAPERValue is the concrete APERValue[NBIoTPagingEDRXInformation].
type NBIoTPagingEDRXInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   NBIoTPagingEDRXInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingEDRXInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXInformationAPERValue) WithoutReplay() NBIoTPagingEDRXInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventL1LoggedMDTConfigAPERValue is the concrete APERValue[EventL1LoggedMDTConfig].
type EventL1LoggedMDTConfigAPERValue struct {
	context s00.BridgeCodecContext
	Value   EventL1LoggedMDTConfig

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventL1LoggedMDTConfigAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventL1LoggedMDTConfigAPERValue) WithoutReplay() EventL1LoggedMDTConfigAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EventTriggerAPERValue is the concrete APERValue[EventTrigger].
type EventTriggerAPERValue struct {
	context s00.BridgeCodecContext
	Value   EventTrigger

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EventTriggerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EventTriggerAPERValue) WithoutReplay() EventTriggerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1ThresholdEventA2APERValue is the concrete APERValue[M1ThresholdEventA2].
type M1ThresholdEventA2APERValue struct {
	context s00.BridgeCodecContext
	Value   M1ThresholdEventA2

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1ThresholdEventA2APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ThresholdEventA2APERValue) WithoutReplay() M1ThresholdEventA2APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNResultToLogAPERValue is the concrete APERValue[MBSFNResultToLog].
type MBSFNResultToLogAPERValue struct {
	context s00.BridgeCodecContext
	Value   MBSFNResultToLog

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MBSFNResultToLogAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogAPERValue) WithoutReplay() MBSFNResultToLogAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MBSFNResultToLogInfoAPERValue is the concrete APERValue[MBSFNResultToLogInfo].
type MBSFNResultToLogInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   MBSFNResultToLogInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MBSFNResultToLogInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MBSFNResultToLogInfoAPERValue) WithoutReplay() MBSFNResultToLogInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionAPERValue is the concrete APERValue[MDTModeExtension].
type MDTModeExtensionAPERValue struct {
	context s00.BridgeCodecContext
	Value   MDTModeExtension

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionAPERValue) WithoutReplay() MDTModeExtensionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECPRelocationIndicationAPERValue is the concrete APERValue[MMECPRelocationIndication].
type MMECPRelocationIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMECPRelocationIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECPRelocationIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECPRelocationIndicationAPERValue) WithoutReplay() MMECPRelocationIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdA2APERValue is the concrete APERValue[MeasurementThresholdA2].
type MeasurementThresholdA2APERValue struct {
	context s00.BridgeCodecContext
	Value   MeasurementThresholdA2

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdA2APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdA2APERValue) WithoutReplay() MeasurementThresholdA2APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementThresholdL1LoggedMDTAPERValue is the concrete APERValue[MeasurementThresholdL1LoggedMDT].
type MeasurementThresholdL1LoggedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   MeasurementThresholdL1LoggedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementThresholdL1LoggedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementThresholdL1LoggedMDTAPERValue) WithoutReplay() MeasurementThresholdL1LoggedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MultiCellLoadReportingResponseAPERValue is the concrete APERValue[MultiCellLoadReportingResponse].
type MultiCellLoadReportingResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   MultiCellLoadReportingResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MultiCellLoadReportingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MultiCellLoadReportingResponseAPERValue) WithoutReplay() MultiCellLoadReportingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MultiCellLoadReportingResponseItemAPERValue is the concrete APERValue[MultiCellLoadReportingResponseItem].
type MultiCellLoadReportingResponseItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   MultiCellLoadReportingResponseItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MultiCellLoadReportingResponseItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MultiCellLoadReportingResponseItemAPERValue) WithoutReplay() MultiCellLoadReportingResponseItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASDeliveryIndicationAPERValue is the concrete APERValue[NASDeliveryIndication].
type NASDeliveryIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   NASDeliveryIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASDeliveryIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASDeliveryIndicationAPERValue) WithoutReplay() NASDeliveryIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NGENBAPERValue is the concrete APERValue[NGENB].
type NGENBAPERValue struct {
	context s00.BridgeCodecContext
	Value   NGENB

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NGENBAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NGENBAPERValue) WithoutReplay() NGENBAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCGIAPERValue is the concrete APERValue[NRCGI].
type NRCGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   NRCGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRCGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCGIAPERValue) WithoutReplay() NRCGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NotificationCellListAPERValue is the concrete APERValue[NotificationCellList].
type NotificationCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   NotificationCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NotificationCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NotificationCellListAPERValue) WithoutReplay() NotificationCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NotificationCellListItemAPERValue is the concrete APERValue[NotificationCellListItem].
type NotificationCellListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   NotificationCellListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NotificationCellListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NotificationCellListItemAPERValue) WithoutReplay() NotificationCellListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5FlowBitRatesAPERValue is the concrete APERValue[PC5FlowBitRates].
type PC5FlowBitRatesAPERValue struct {
	context s00.BridgeCodecContext
	Value   PC5FlowBitRates

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5FlowBitRatesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5FlowBitRatesAPERValue) WithoutReplay() PC5FlowBitRatesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueERABIEContainerList, error)
	encode  func(NASNonDeliveryIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndicationIEValueERABIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) New(value NASNonDeliveryIndicationIEValueERABIEContainerList) (NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value NASNonDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value NASNonDeliveryIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueERABIEContainerList []NASNonDeliveryIndicationIEValueProtocolIESingleContainer

// NASNonDeliveryIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEField, error)
	encode  func(NASNonDeliveryIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndicationIEField, aper.DecodeState) (NASNonDeliveryIndicationIEField, aper.Snapshot)
	compare func(NASNonDeliveryIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationIEFieldValueCodec) New(value NASNonDeliveryIndicationIEField) (NASNonDeliveryIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationIEFieldValueCodec) EncodeAPER(value NASNonDeliveryIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASNonDeliveryIndicationIEFieldValueCodec) encodeBudgetValue(value NASNonDeliveryIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationIEFieldValueCodec) encodeChanged(value NASNonDeliveryIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEContainer, error)
	encode  func(NASNonDeliveryIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndicationIEContainer, aper.DecodeState) (NASNonDeliveryIndicationIEContainer, aper.Snapshot)
	compare func(NASNonDeliveryIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationIEContainerValueCodec) New(value NASNonDeliveryIndicationIEContainer) (NASNonDeliveryIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationIEContainerValueCodec) EncodeAPER(value NASNonDeliveryIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASNonDeliveryIndicationIEContainerValueCodec) encodeBudgetValue(value NASNonDeliveryIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationIEContainerValueCodec) encodeChanged(value NASNonDeliveryIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList []NASNonDeliveryIndicationIEValueProtocolIESingleContainer

// NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolIEContainerList, error)
	encode  func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) New(value NASNonDeliveryIndicationIEValueProtocolIEContainerList) (NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value NASNonDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value NASNonDeliveryIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASNonDeliveryIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueProtocolIEContainerList []NASNonDeliveryIndicationIEValueProtocolIESingleContainer

// NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASNonDeliveryIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[NASNonDeliveryIndicationIEValue].
type NASNonDeliveryIndicationIEValueProtocolIESingleContainer = NASNonDeliveryIndicationIEField

// NASNonDeliveryIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASNonDeliveryIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEFieldAPERValue) WithoutReplay() NASNonDeliveryIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASNonDeliveryIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEContainerAPERValue) WithoutReplay() NASNonDeliveryIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[NASNonDeliveryIndicationIEValue]].
type NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         NASNonDeliveryIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APContextatSource(v *ContextatSource, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APGlobalRANNODEID(&v.SourceNGRANNodeID, s)
	s00.BridgeCaptureS1APRANUENGAPID(&v.RANUENGAPID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeContextatSourceExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APContextatSource(v *ContextatSource, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APGlobalRANNODEID(&v.SourceNGRANNodeID, s)
	s06.BridgeCompareS1APRANUENGAPID(&v.RANUENGAPID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeContextatSourceExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEventL1LoggedMDTConfig(v *EventL1LoggedMDTConfig, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APMeasurementThresholdL1LoggedMDT(&v.L1Threshold, s)
	s00.BridgeCaptureS1APHysteresis(&v.Hysteresis, s)
	s00.BridgeCaptureS1APTimeToTrigger(&v.TimeToTrigger, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEventL1LoggedMDTConfig(v *EventL1LoggedMDTConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APMeasurementThresholdL1LoggedMDT(&v.L1Threshold, s)
	s02.BridgeCompareS1APHysteresis(&v.Hysteresis, s)
	s07.BridgeCompareS1APTimeToTrigger(&v.TimeToTrigger, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEventTrigger(v *EventTrigger, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.EventTriggerChoiceOutOfCoverage:
		{
			f := s.Begin()
			s.Bool(v.OutOfCoverage == nil)
			if v.OutOfCoverage != nil {
				s.Int(int64((*v.OutOfCoverage)))
			}
			s.End(f, nil, false)
		}
	case s00.EventTriggerChoiceEventL1LoggedMDTConfig:
		{
			f := s.Begin()
			s.Bool(v.EventL1LoggedMDTConfig == nil)
			if v.EventL1LoggedMDTConfig != nil {
				BridgeCaptureS1APEventL1LoggedMDTConfig(v.EventL1LoggedMDTConfig, s)
			}
			s.End(f, nil, false)
		}
	case s00.EventTriggerChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				s13.BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEventTrigger(v *EventTrigger, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.EventTriggerChoiceOutOfCoverage:
		{
			f := s.Begin()
			s.Bool(v.OutOfCoverage == nil)
			if v.OutOfCoverage != nil {
				s.Int(int64((*v.OutOfCoverage)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.EventTriggerChoiceEventL1LoggedMDTConfig:
		{
			f := s.Begin()
			s.Bool(v.EventL1LoggedMDTConfig == nil)
			if v.EventL1LoggedMDTConfig != nil {
				BridgeCompareS1APEventL1LoggedMDTConfig(v.EventL1LoggedMDTConfig, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.EventTriggerChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				s13.BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APGlobalRANNODEID(v *GlobalRANNODEID, s *aper.SemanticCapture) {
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
	case s00.GlobalRANNODEIDChoiceGNB:
		{
			f := s.Begin()
			s.Bool(v.GNB == nil)
			if v.GNB != nil {
				s18.BridgeCaptureS1APGNB(v.GNB, s)
			}
			s.End(f, nil, false)
		}
	case s00.GlobalRANNODEIDChoiceNgENB:
		{
			f := s.Begin()
			s.Bool(v.NgENB == nil)
			if v.NgENB != nil {
				BridgeCaptureS1APNGENB(v.NgENB, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGlobalRANNODEID(v *GlobalRANNODEID, s *aper.SemanticComparison) {
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
	case s00.GlobalRANNODEIDChoiceGNB:
		{
			f := s.Begin()
			s.Bool(v.GNB == nil)
			if v.GNB != nil {
				s18.BridgeCompareS1APGNB(v.GNB, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.GlobalRANNODEIDChoiceNgENB:
		{
			f := s.Begin()
			s.Bool(v.NgENB == nil)
			if v.NgENB != nil {
				BridgeCompareS1APNGENB(v.NgENB, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLoggedMDTTrigger(v *LoggedMDTTrigger, s *aper.SemanticCapture) {
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
	case s00.LoggedMDTTriggerChoicePeriodical:
		{
			f := s.Begin()
			s.Bool(v.Periodical == nil)
			if v.Periodical != nil {
			}
			s.End(f, nil, false)
		}
	case s00.LoggedMDTTriggerChoiceEventTrigger:
		{
			f := s.Begin()
			s.Bool(v.EventTrigger == nil)
			if v.EventTrigger != nil {
				BridgeCaptureS1APEventTrigger(v.EventTrigger, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLoggedMDTTrigger(v *LoggedMDTTrigger, s *aper.SemanticComparison) {
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
	case s00.LoggedMDTTriggerChoicePeriodical:
		{
			f := s.Begin()
			s.Bool(v.Periodical == nil)
			if v.Periodical != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LoggedMDTTriggerChoiceEventTrigger:
		{
			f := s.Begin()
			s.Bool(v.EventTrigger == nil)
			if v.EventTrigger != nil {
				BridgeCompareS1APEventTrigger(v.EventTrigger, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM1ThresholdEventA2(v *M1ThresholdEventA2, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APMeasurementThresholdA2(&v.MeasurementThreshold, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM1ThresholdEventA2(v *M1ThresholdEventA2, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APMeasurementThresholdA2(&v.MeasurementThreshold, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM3Configuration(v *M3Configuration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APM3period(&v.M3period, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM3Configuration(v *M3Configuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APM3period(&v.M3period, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM4Configuration(v *M4Configuration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APM4period(&v.M4period, s)
	s00.BridgeCaptureS1APLinksToLog(&v.M4LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM4Configuration(v *M4Configuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APM4period(&v.M4period, s)
	s02.BridgeCompareS1APLinksToLog(&v.M4LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM5Configuration(v *M5Configuration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APM5period(&v.M5period, s)
	s00.BridgeCaptureS1APLinksToLog(&v.M5LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM5Configuration(v *M5Configuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APM5period(&v.M5period, s)
	s02.BridgeCompareS1APLinksToLog(&v.M5LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM6Configuration(v *M6Configuration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APM6reportInterval(&v.M6reportInterval, s)
	{
		f := s.Begin()
		s.Bool(v.M6delayThreshold == nil)
		if v.M6delayThreshold != nil {
			s00.BridgeCaptureS1APM6delayThreshold(v.M6delayThreshold, s)
		}
		s.End(f, nil, false)
	}
	s00.BridgeCaptureS1APLinksToLog(&v.M6LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM6Configuration(v *M6Configuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APM6reportInterval(&v.M6reportInterval, s)
	{
		f := s.Begin()
		s.Bool(v.M6delayThreshold == nil)
		if v.M6delayThreshold != nil {
			s02.BridgeCompareS1APM6delayThreshold(v.M6delayThreshold, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s02.BridgeCompareS1APLinksToLog(&v.M6LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM7Configuration(v *M7Configuration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APM7period(&v.M7period, s)
	s00.BridgeCaptureS1APLinksToLog(&v.M7LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM7Configuration(v *M7Configuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APM7period(&v.M7period, s)
	s02.BridgeCompareS1APLinksToLog(&v.M7LinksToLog, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMBSFNResultToLogInfo(v *MBSFNResultToLogInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.MBSFNAreaId == nil)
		if v.MBSFNAreaId != nil {
			s.Int(int64((*v.MBSFNAreaId)))
		}
		s.End(f, nil, false)
	}
	s00.BridgeCaptureS1APEARFCN(&v.CarrierFreq, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMBSFNResultToLogInfo(v *MBSFNResultToLogInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.MBSFNAreaId == nil)
		if v.MBSFNAreaId != nil {
			s.Int(int64((*v.MBSFNAreaId)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s02.BridgeCompareS1APEARFCN(&v.CarrierFreq, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMDTModeExtension(v *MDTModeExtension, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMDTModeExtension(v *MDTModeExtension, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	s.Int(int64(v.Value.Class))
	s.Int(int64(v.Value.Tag))
	s.Bool(v.Value.Constructed)
	s.Bytes(v.Value.Bytes)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMECPRelocationIndication(v *MMECPRelocationIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMECPRelocationIndication(v *MMECPRelocationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMeasurementThresholdA2(v *MeasurementThresholdA2, s *aper.SemanticCapture) {
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
	case s00.MeasurementThresholdA2ChoiceThresholdRSRP:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRP == nil)
			if v.ThresholdRSRP != nil {
				s00.BridgeCaptureS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, nil, false)
		}
	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s00.BridgeCaptureS1APThresholdRSRQ(v.ThresholdRSRQ, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMeasurementThresholdA2(v *MeasurementThresholdA2, s *aper.SemanticComparison) {
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
	case s00.MeasurementThresholdA2ChoiceThresholdRSRP:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRP == nil)
			if v.ThresholdRSRP != nil {
				s07.BridgeCompareS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s07.BridgeCompareS1APThresholdRSRQ(v.ThresholdRSRQ, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMeasurementThresholdL1LoggedMDT(v *MeasurementThresholdL1LoggedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRP == nil)
			if v.ThresholdRSRP != nil {
				s00.BridgeCaptureS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, nil, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s00.BridgeCaptureS1APThresholdRSRQ(v.ThresholdRSRQ, s)
			}
			s.End(f, nil, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				s13.BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMeasurementThresholdL1LoggedMDT(v *MeasurementThresholdL1LoggedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRP == nil)
			if v.ThresholdRSRP != nil {
				s07.BridgeCompareS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s07.BridgeCompareS1APThresholdRSRQ(v.ThresholdRSRQ, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				s13.BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMultiCellLoadReportingResponseItem(v *MultiCellLoadReportingResponseItem, s *aper.SemanticCapture) {
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
	case s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		{
			f := s.Begin()
			s.Bool(v.EUTRANResponse == nil)
			if v.EUTRANResponse != nil {
				s17.BridgeCaptureS1APEUTRANResponse(v.EUTRANResponse, s)
			}
			s.End(f, nil, false)
		}
	case s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		s.Bytes(v.UTRANResponse)
	case s00.MultiCellLoadReportingResponseItemChoiceGERANResponse:
		s.Bytes(v.GERANResponse)
	case s00.MultiCellLoadReportingResponseItemChoiceEHRPD:
		{
			f := s.Begin()
			s.Bool(v.EHRPD == nil)
			if v.EHRPD != nil {
				s15.BridgeCaptureS1APEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APMultiCellLoadReportingResponseItem(v *MultiCellLoadReportingResponseItem, s *aper.SemanticComparison) {
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
	case s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		{
			f := s.Begin()
			s.Bool(v.EUTRANResponse == nil)
			if v.EUTRANResponse != nil {
				s17.BridgeCompareS1APEUTRANResponse(v.EUTRANResponse, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		s.Bytes(v.UTRANResponse)
	case s00.MultiCellLoadReportingResponseItemChoiceGERANResponse:
		s.Bytes(v.GERANResponse)
	case s00.MultiCellLoadReportingResponseItemChoiceEHRPD:
		{
			f := s.Begin()
			s.Bool(v.EHRPD == nil)
			if v.EHRPD != nil {
				s15.BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APMutingPatternInformation(v *MutingPatternInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MutingPatternPeriod))
	{
		f := s.Begin()
		s.BigInt(v.MutingPatternOffset)
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMutingPatternInformation(v *MutingPatternInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MutingPatternPeriod))
	{
		f := s.Begin()
		s.BigInt(v.MutingPatternOffset)
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNASDeliveryIndication(v *NASDeliveryIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNASDeliveryIndication(v *NASDeliveryIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s13.BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNASNonDeliveryIndicationIEValue(v *NASNonDeliveryIndicationIEValue, s *aper.SemanticCapture) {
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
func (v NASNonDeliveryIndicationIEValue) captureSemantics(s aper.SemanticCapture) NASNonDeliveryIndicationIEValue {
	BridgeCaptureS1APNASNonDeliveryIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APNASNonDeliveryIndicationIEValue(v *NASNonDeliveryIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s02.BridgeCompareS1APNASPDU(v.rowNASPDU, s)
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
func (v NASNonDeliveryIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APNASNonDeliveryIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APNBIoTPagingEDRXInformation(v *NBIoTPagingEDRXInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APNBIoTPagingEDRXCycle(&v.NBIoTPagingEDRXCycle, s)
	{
		f := s.Begin()
		s.Bool(v.NBIoTPagingTimeWindow == nil)
		if v.NBIoTPagingTimeWindow != nil {
			s00.BridgeCaptureS1APNBIoTPagingTimeWindow(v.NBIoTPagingTimeWindow, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNBIoTPagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNBIoTPagingEDRXInformation(v *NBIoTPagingEDRXInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APNBIoTPagingEDRXCycle(&v.NBIoTPagingEDRXCycle, s)
	{
		f := s.Begin()
		s.Bool(v.NBIoTPagingTimeWindow == nil)
		if v.NBIoTPagingTimeWindow != nil {
			s02.BridgeCompareS1APNBIoTPagingTimeWindow(v.NBIoTPagingTimeWindow, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNBIoTPagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNGENB(v *NGENB, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APGlobalENBID(&v.GlobalNgENBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNGENBExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNGENB(v *NGENB, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APGlobalENBID(&v.GlobalNgENBID, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNGENBExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNRCGI(v *NRCGI, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureS1APNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRCGIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNRCGI(v *NRCGI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNIdentity, s)
	s02.BridgeCompareS1APNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRCGIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNRUESecurityCapabilities(v *NRUESecurityCapabilities, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APNRencryptionAlgorithms(&v.NRencryptionAlgorithms, s)
	s00.BridgeCaptureS1APNRintegrityProtectionAlgorithms(&v.NRintegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNRUESecurityCapabilities(v *NRUESecurityCapabilities, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APNRencryptionAlgorithms(&v.NRencryptionAlgorithms, s)
	s02.BridgeCompareS1APNRintegrityProtectionAlgorithms(&v.NRintegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v *NRUESidelinkAggregateMaximumBitrate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.UEaggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v *NRUESidelinkAggregateMaximumBitrate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.UEaggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNRV2XServicesAuthorized(v *NRV2XServicesAuthorized, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.VehicleUE == nil)
		if v.VehicleUE != nil {
			s00.BridgeCaptureS1APVehicleUE(v.VehicleUE, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PedestrianUE == nil)
		if v.PedestrianUE != nil {
			s00.BridgeCaptureS1APPedestrianUE(v.PedestrianUE, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNRV2XServicesAuthorized(v *NRV2XServicesAuthorized, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.VehicleUE == nil)
		if v.VehicleUE != nil {
			s07.BridgeCompareS1APVehicleUE(v.VehicleUE, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.PedestrianUE == nil)
		if v.PedestrianUE != nil {
			s02.BridgeCompareS1APPedestrianUE(v.PedestrianUE, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNotificationCellListItem(v *NotificationCellListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s00.BridgeCaptureS1APNotifyFlag(&v.NotifyFlag, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNotificationCellListItem(v *NotificationCellListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.CellID)
	s02.BridgeCompareS1APNotifyFlag(&v.NotifyFlag, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APOverloadResponse(v *OverloadResponse, s *aper.SemanticCapture) {
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
	case s00.OverloadResponseChoiceOverloadAction:
		{
			f := s.Begin()
			s.Bool(v.OverloadAction == nil)
			if v.OverloadAction != nil {
				s00.BridgeCaptureS1APOverloadAction(v.OverloadAction, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APOverloadResponse(v *OverloadResponse, s *aper.SemanticComparison) {
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
	case s00.OverloadResponseChoiceOverloadAction:
		{
			f := s.Begin()
			s.Bool(v.OverloadAction == nil)
			if v.OverloadAction != nil {
				s02.BridgeCompareS1APOverloadAction(v.OverloadAction, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPC5FlowBitRates(v *PC5FlowBitRates, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.GuaranteedFlowBitRate, s)
	s00.BridgeCaptureS1APBitRate(&v.MaximumFlowBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPC5FlowBitRates(v *PC5FlowBitRates, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.GuaranteedFlowBitRate, s)
	s02.BridgeCompareS1APBitRate(&v.MaximumFlowBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// ContextatSource represents the ASN.1 type ContextatSource (SEQUENCE).
type ContextatSource struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	SourceNGRANNodeID GlobalRANNODEID                       `asn1:"tag:0,context,explicit"`
	RANUENGAPID       s00.RANUENGAPID                       `asn1:"tag:1,context,implicit"`
	IEExtensions      s07.ContextatSourceExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// EventL1LoggedMDTConfig represents the ASN.1 type EventL1LoggedMDTConfig (SEQUENCE).
type EventL1LoggedMDTConfig struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	L1Threshold       MeasurementThresholdL1LoggedMDT              `asn1:"tag:0,context,explicit"`
	Hysteresis        s00.Hysteresis                               `asn1:"tag:1,context,implicit"`
	TimeToTrigger     s00.TimeToTrigger                            `asn1:"tag:2,context,implicit"`
	IEExtensions      s09.EventL1LoggedMDTConfigExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// EventTrigger represents the ASN.1 CHOICE type EventTrigger.
type EventTrigger struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	Choice                 int
	perPadding             aper.CompletePadding                                 `json:"-"`
	perOpenTypePadding     aper.CompletePadding                                 `json:"-"`
	OutOfCoverage          *int64                                               `json:"OutOfCoverage,omitempty"`
	EventL1LoggedMDTConfig *EventL1LoggedMDTConfig                              `json:"EventL1LoggedMDTConfig,omitempty"`
	ChoiceExtensions       *s09.EventTriggerExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
}

// LoggedMDTTrigger represents the ASN.1 CHOICE type LoggedMDTTrigger.
type LoggedMDTTrigger struct {
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
	Periodical         *struct{}             `json:"Periodical,omitempty"`
	EventTrigger       *EventTrigger         `json:"EventTrigger,omitempty"`
}

// M3Configuration represents the ASN.1 type M3Configuration (SEQUENCE).
type M3Configuration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	M3period          s00.M3period                          `asn1:"tag:0,context,implicit"`
	IEExtensions      s10.M3ConfigurationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// M4Configuration represents the ASN.1 type M4Configuration (SEQUENCE).
type M4Configuration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	M4period          s00.M4period                          `asn1:"tag:0,context,implicit"`
	M4LinksToLog      s00.LinksToLog                        `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.M4ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// M5Configuration represents the ASN.1 type M5Configuration (SEQUENCE).
type M5Configuration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	M5period          s00.M5period                          `asn1:"tag:0,context,implicit"`
	M5LinksToLog      s00.LinksToLog                        `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.M5ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// M6Configuration represents the ASN.1 type M6Configuration (SEQUENCE).
type M6Configuration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	M6reportInterval  s00.M6reportInterval                  `asn1:"tag:0,context,implicit"`
	M6delayThreshold  *s00.M6delayThreshold                 `asn1:"tag:1,context,implicit,optional" json:"M6delayThreshold,omitempty"`
	M6LinksToLog      s00.LinksToLog                        `asn1:"tag:2,context,implicit"`
	IEExtensions      s10.M6ConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// M7Configuration represents the ASN.1 type M7Configuration (SEQUENCE).
type M7Configuration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	M7period          s00.M7period                          `asn1:"tag:0,context,implicit"`
	M7LinksToLog      s00.LinksToLog                        `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.M7ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type MBSFNResultToLog = []MBSFNResultToLogInfo

// MBSFNResultToLogInfo represents the ASN.1 type MBSFN-ResultToLogInfo (SEQUENCE).
type MBSFNResultToLogInfo struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MBSFNAreaId       *int64                                     `asn1:"tag:0,context,implicit,optional" json:"MBSFNAreaId,omitempty"`
	CarrierFreq       s00.EARFCN                                 `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.MBSFNResultToLogInfoExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                       `asn1:"-" json:"-"`
	extCount          int64                                      `asn1:"-" json:"-"`
	extPresent        []bool                                     `asn1:"-" json:"-"`
	extData           [][]byte                                   `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MDTModeExtension represents the ASN.1 type MDTMode-Extension (SEQUENCE).
type MDTModeExtension struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Id               s00.ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            runtime.RawValue     `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// MeasurementThresholdA2 represents the ASN.1 CHOICE type MeasurementThresholdA2.
type MeasurementThresholdA2 struct {
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
	ThresholdRSRP      *s00.ThresholdRSRP    `json:"ThresholdRSRP,omitempty"`
	ThresholdRSRQ      *s00.ThresholdRSRQ    `json:"ThresholdRSRQ,omitempty"`
}

// MeasurementThresholdL1LoggedMDT represents the ASN.1 CHOICE type MeasurementThresholdL1LoggedMDT.
type MeasurementThresholdL1LoggedMDT struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding                                                    `json:"-"`
	perOpenTypePadding aper.CompletePadding                                                    `json:"-"`
	ThresholdRSRP      *s00.ThresholdRSRP                                                      `json:"ThresholdRSRP,omitempty"`
	ThresholdRSRQ      *s00.ThresholdRSRQ                                                      `json:"ThresholdRSRQ,omitempty"`
	ChoiceExtensions   *s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
}

// MutingPatternInformation represents the ASN.1 type MutingPatternInformation (SEQUENCE).
type MutingPatternInformation struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	MutingPatternPeriod int64                                          `asn1:"tag:0,context,implicit"`
	MutingPatternOffset *big.Int                                       `asn1:"tag:1,context,implicit,optional" json:"MutingPatternOffset,omitempty"`
	IEExtensions        s10.MutingPatternInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                           `asn1:"-" json:"-"`
	extCount            int64                                          `asn1:"-" json:"-"`
	extPresent          []bool                                         `asn1:"-" json:"-"`
	extData             [][]byte                                       `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// NBIoTPagingEDRXInformation represents the ASN.1 type NB-IoT-Paging-eDRXInformation (SEQUENCE).
type NBIoTPagingEDRXInformation struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	NBIoTPagingEDRXCycle  s00.NBIoTPagingEDRXCycle                         `asn1:"tag:0,context,implicit"`
	NBIoTPagingTimeWindow *s00.NBIoTPagingTimeWindow                       `asn1:"tag:1,context,implicit,optional" json:"NBIoTPagingTimeWindow,omitempty"`
	IEExtensions          s10.NBIoTPagingEDRXInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                             `asn1:"-" json:"-"`
	extCount              int64                                            `asn1:"-" json:"-"`
	extPresent            []bool                                           `asn1:"-" json:"-"`
	extData               [][]byte                                         `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PLMNIdentity      s00.PLMNidentity            `asn1:"tag:0,context,implicit"`
	NRCellIdentity    s00.NRCellIdentity          `asn1:"tag:1,context,implicit"`
	IEExtensions      s10.NRCGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                        `asn1:"-" json:"-"`
	extCount          int64                       `asn1:"-" json:"-"`
	extPresent        []bool                      `asn1:"-" json:"-"`
	extData           [][]byte                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NRUESecurityCapabilities represents the ASN.1 type NRUESecurityCapabilities (SEQUENCE).
type NRUESecurityCapabilities struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	NRencryptionAlgorithms          s00.NRencryptionAlgorithms                     `asn1:"tag:0,context,implicit"`
	NRintegrityProtectionAlgorithms s00.NRintegrityProtectionAlgorithms            `asn1:"tag:1,context,implicit"`
	IEExtensions                    s10.NRUESecurityCapabilitiesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef               bool                                           `asn1:"-" json:"-"`
	extCount                        int64                                          `asn1:"-" json:"-"`
	extPresent                      []bool                                         `asn1:"-" json:"-"`
	extData                         [][]byte                                       `asn1:"-" json:"-"`
	perPadding                      aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding                   []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin                       []aper.OpaqueOrigin
	extWire                         []aper.WireSpan
}

// NRV2XServicesAuthorized represents the ASN.1 type NRV2XServicesAuthorized (SEQUENCE).
type NRV2XServicesAuthorized struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	VehicleUE         *s00.VehicleUE                                `asn1:"tag:0,context,implicit,optional" json:"VehicleUE,omitempty"`
	PedestrianUE      *s00.PedestrianUE                             `asn1:"tag:1,context,implicit,optional" json:"PedestrianUE,omitempty"`
	IEExtensions      s10.NRV2XServicesAuthorizedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NRUESidelinkAggregateMaximumBitrate represents the ASN.1 type NRUESidelinkAggregateMaximumBitrate (SEQUENCE).
type NRUESidelinkAggregateMaximumBitrate struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	UEaggregateMaximumBitRate s00.BitRate                                               `asn1:"tag:0,context,implicit"`
	IEExtensions              s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                      `asn1:"-" json:"-"`
	extCount                  int64                                                     `asn1:"-" json:"-"`
	extPresent                []bool                                                    `asn1:"-" json:"-"`
	extData                   [][]byte                                                  `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// OverloadResponse represents the ASN.1 CHOICE type OverloadResponse.
type OverloadResponse struct {
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
	OverloadAction     *s00.OverloadAction   `json:"OverloadAction,omitempty"`
}

// PC5FlowBitRates represents the ASN.1 type PC5FlowBitRates (SEQUENCE).
type PC5FlowBitRates struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	GuaranteedFlowBitRate s00.BitRate                           `asn1:"tag:0,context,implicit"`
	MaximumFlowBitRate    s00.BitRate                           `asn1:"tag:1,context,implicit"`
	IEExtensions          s10.PC5FlowBitRatesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                  `asn1:"-" json:"-"`
	extCount              int64                                 `asn1:"-" json:"-"`
	extPresent            []bool                                `asn1:"-" json:"-"`
	extData               [][]byte                              `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// GlobalRANNODEID represents the ASN.1 CHOICE type Global-RAN-NODE-ID.
type GlobalRANNODEID struct {
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
	GNB                *s18.GNB              `json:"GNB,omitempty"`
	NgENB              *NGENB                `json:"NgENB,omitempty"`
}

// NGENB represents the ASN.1 type NG-eNB (SEQUENCE).
type NGENB struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalNgENBID     s18.GlobalENBID             `asn1:"tag:0,context,implicit"`
	IEExtensions      s10.NGENBExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                        `asn1:"-" json:"-"`
	extCount          int64                       `asn1:"-" json:"-"`
	extPresent        []bool                      `asn1:"-" json:"-"`
	extData           [][]byte                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// M1ThresholdEventA2 represents the ASN.1 type M1ThresholdEventA2 (SEQUENCE).
type M1ThresholdEventA2 struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	MeasurementThreshold MeasurementThresholdA2                   `asn1:"tag:0,context,explicit"`
	IEExtensions         s10.M1ThresholdEventA2ExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                     `asn1:"-" json:"-"`
	extCount             int64                                    `asn1:"-" json:"-"`
	extPresent           []bool                                   `asn1:"-" json:"-"`
	extData              [][]byte                                 `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// MarshalAPER encodes ContextatSource to APER format.
func (v *ContextatSource) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ContextatSource) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.SourceNGRANNodeID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sourceNG-RAN-node-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.RANUENGAPID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
		return fmt.Errorf("encoding rAN-UE-NGAP-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s07.BridgeContextatSourceExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ContextatSource from APER format.
func (v *ContextatSource) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ContextatSource with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ContextatSource) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ContextatSource")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ContextatSource")
	}
	padding, err := aper.CaptureFinalBits(bb, "ContextatSource")
	if err != nil {
		return runtime.WrapDecodePath(err, "ContextatSource")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ContextatSource) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ContextatSource{}
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
	toleranceMark_sourcengrannodeid := bb.EnterComponent("SourceNGRANNodeID")
	if err := v.SourceNGRANNodeID.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceNGRANNodeID")
	}
	bb.LeaveComponent(toleranceMark_sourcengrannodeid)
	val_ranuengapid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RANUENGAPID")
	}
	v.RANUENGAPID = s00.RANUENGAPID(val_ranuengapid)
	if opt_ieextensions {
		tmp_ieextensions := make(s07.ContextatSourceExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s07.ContextatSourceExtIEsExtField
				if err := s07.BridgeContextatSourceExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes EventL1LoggedMDTConfig to APER format.
func (v *EventL1LoggedMDTConfig) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EventL1LoggedMDTConfig) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.L1Threshold.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding l1Threshold: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Hysteresis), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(30), false); err != nil {
		return fmt.Errorf("encoding hysteresis: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.TimeToTrigger), 16, false); err != nil {
		return fmt.Errorf("encoding timeToTrigger: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes EventL1LoggedMDTConfig from APER format.
func (v *EventL1LoggedMDTConfig) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EventL1LoggedMDTConfig with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EventL1LoggedMDTConfig) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	padding, err := aper.CaptureFinalBits(bb, "EventL1LoggedMDTConfig")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EventL1LoggedMDTConfig) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventL1LoggedMDTConfig{}
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
	if err := v.L1Threshold.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "L1Threshold")
	}
	val_hysteresis, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(30), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Hysteresis")
	}
	v.Hysteresis = s00.Hysteresis(val_hysteresis)
	val_timetotrigger, err := aper.DecodeEnumeratedAligned(bb, 16, false, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeToTrigger"})
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeToTrigger")
	}
	v.TimeToTrigger = s00.TimeToTrigger(val_timetotrigger)
	if opt_ieextensions {
		tmp_ieextensions := make(s09.EventL1LoggedMDTConfigExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.EventL1LoggedMDTConfigExtIEsExtField
				if err := s09.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes EventTrigger to APER format.
func (v *EventTrigger) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *EventTrigger) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "EventTrigger:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.EventTriggerChoiceOutOfCoverage:
		if v.OutOfCoverage == nil {
			return fmt.Errorf("choice alternative outOfCoverage is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.OutOfCoverage), 1, true); err != nil {
			return fmt.Errorf("encoding outOfCoverage: %w", err)
		}
	case s00.EventTriggerChoiceEventL1LoggedMDTConfig:
		if v.EventL1LoggedMDTConfig == nil {
			return fmt.Errorf("choice alternative eventL1LoggedMDTConfig is nil")
		}
		if err := v.EventL1LoggedMDTConfig.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding eventL1LoggedMDTConfig: %w", err)
		}
	case s00.EventTriggerChoiceChoiceExtensions:
		if v.ChoiceExtensions == nil {
			return fmt.Errorf("choice alternative choice-Extensions is nil")
		}
		if err := s09.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding choice-Extensions: %w", err)
		}
	default:
		return fmt.Errorf("unknown EventTrigger choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes EventTrigger from APER format.
func (v *EventTrigger) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EventTrigger with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EventTrigger) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTrigger")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventTrigger")
	}
	padding, err := aper.CaptureFinalBits(bb, "EventTrigger")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventTrigger")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *EventTrigger) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventTrigger{}
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
	case s00.EventTriggerChoiceOutOfCoverage:
		val_outofcoverage, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OutOfCoverage"})
		if err != nil {
			return runtime.WrapDecodePath(err, "OutOfCoverage")
		}
		if err := aper.ChargeValue(bb, val_outofcoverage); err != nil {
			return err
		}
		v.OutOfCoverage = (*int64)(bb.OwnInt64(int64(val_outofcoverage)))

	case s00.EventTriggerChoiceEventL1LoggedMDTConfig:
		toleranceMark_eventl1loggedmdtconfig := bb.EnterComponent("EventL1LoggedMDTConfig")
		var dec_eventl1loggedmdtconfig EventL1LoggedMDTConfig
		if err := dec_eventl1loggedmdtconfig.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
		}
		if err := aper.ChargeValue(bb, dec_eventl1loggedmdtconfig); err != nil {
			return err
		}
		v.EventL1LoggedMDTConfig = &dec_eventl1loggedmdtconfig
		bb.LeaveComponent(toleranceMark_eventl1loggedmdtconfig)
	case s00.EventTriggerChoiceChoiceExtensions:
		var dec_choiceextensions s09.EventTriggerExtIEValueProtocolIESingleContainer
		if err := s09.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes LoggedMDTTrigger to APER format.
func (v *LoggedMDTTrigger) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *LoggedMDTTrigger) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "LoggedMDTTrigger:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "LoggedMDTTrigger:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "LoggedMDTTrigger:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "LoggedMDTTrigger:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.LoggedMDTTriggerChoicePeriodical:
	case s00.LoggedMDTTriggerChoiceEventTrigger:
		if v.EventTrigger == nil {
			return fmt.Errorf("choice alternative eventTrigger is nil")
		}
		if err := v.EventTrigger.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding eventTrigger: %w", err)
		}
	default:
		return fmt.Errorf("unknown LoggedMDTTrigger choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LoggedMDTTrigger from APER format.
func (v *LoggedMDTTrigger) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LoggedMDTTrigger with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LoggedMDTTrigger) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDTTrigger")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDTTrigger")
	}
	padding, err := aper.CaptureFinalBits(bb, "LoggedMDTTrigger")
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDTTrigger")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *LoggedMDTTrigger) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMDTTrigger{}
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
	case s00.LoggedMDTTriggerChoicePeriodical:
		v.Periodical = new(struct{})
	case s00.LoggedMDTTriggerChoiceEventTrigger:
		toleranceMark_eventtrigger := bb.EnterComponent("EventTrigger")
		var dec_eventtrigger EventTrigger
		if err := dec_eventtrigger.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "EventTrigger")
		}
		if err := aper.ChargeValue(bb, dec_eventtrigger); err != nil {
			return err
		}
		v.EventTrigger = &dec_eventtrigger
		bb.LeaveComponent(toleranceMark_eventtrigger)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes M3Configuration to APER format.
func (v *M3Configuration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M3Configuration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M3period), 3, true); err != nil {
		return fmt.Errorf("encoding m3period: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M3Configuration from APER format.
func (v *M3Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M3Configuration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M3Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M3Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M3Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M3Configuration{}
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
	val_m3period, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 7, Path: "M3period"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M3period")
	}
	v.M3period = s00.M3period(val_m3period)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M3ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M3ConfigurationExtIEsExtField
				if err := s10.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M4Configuration to APER format.
func (v *M4Configuration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M4Configuration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M4period), 5, true); err != nil {
		return fmt.Errorf("encoding m4period: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M4LinksToLog), 3, true); err != nil {
		return fmt.Errorf("encoding m4-links-to-log: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M4Configuration from APER format.
func (v *M4Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M4Configuration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M4Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M4Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M4Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M4Configuration{}
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
	val_m4period, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M4period"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M4period")
	}
	v.M4period = s00.M4period(val_m4period)
	val_m4linkstolog, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M4LinksToLog"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M4LinksToLog")
	}
	v.M4LinksToLog = s00.LinksToLog(val_m4linkstolog)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M4ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M4ConfigurationExtIEsExtField
				if err := s10.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M5Configuration to APER format.
func (v *M5Configuration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M5Configuration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M5period), 5, true); err != nil {
		return fmt.Errorf("encoding m5period: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M5LinksToLog), 3, true); err != nil {
		return fmt.Errorf("encoding m5-links-to-log: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M5Configuration from APER format.
func (v *M5Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M5Configuration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M5Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M5Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M5Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M5Configuration{}
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
	val_m5period, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M5period"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M5period")
	}
	v.M5period = s00.M5period(val_m5period)
	val_m5linkstolog, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M5LinksToLog"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M5LinksToLog")
	}
	v.M5LinksToLog = s00.LinksToLog(val_m5linkstolog)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M5ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M5ConfigurationExtIEsExtField
				if err := s10.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M6Configuration to APER format.
func (v *M6Configuration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M6Configuration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.M6delayThreshold != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M6reportInterval), 4, true); err != nil {
		return fmt.Errorf("encoding m6report-Interval: %w", err)
	}
	if v.M6delayThreshold != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.M6delayThreshold), 12, true); err != nil {
			return fmt.Errorf("encoding m6delay-threshold: %w", err)
		}
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M6LinksToLog), 3, true); err != nil {
		return fmt.Errorf("encoding m6-links-to-log: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M6Configuration from APER format.
func (v *M6Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M6Configuration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M6Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M6Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M6Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M6Configuration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_m6delaythreshold, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_m6reportinterval, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M6reportInterval"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M6reportInterval")
	}
	v.M6reportInterval = s00.M6reportInterval(val_m6reportinterval)
	if opt_m6delaythreshold {
		val_m6delaythreshold, err := aper.DecodeEnumeratedAligned(bb, 12, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M6delayThreshold"})
		if err != nil {
			return runtime.WrapDecodePath(err, "M6delayThreshold")
		}
		tmp_m6delaythreshold := s00.M6delayThreshold(val_m6delaythreshold)
		if err := aper.ChargeValue(bb, tmp_m6delaythreshold); err != nil {
			return err
		}
		v.M6delayThreshold = (*s00.M6delayThreshold)(bb.OwnInt64(int64(tmp_m6delaythreshold)))

	}
	val_m6linkstolog, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M6LinksToLog"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M6LinksToLog")
	}
	v.M6LinksToLog = s00.LinksToLog(val_m6linkstolog)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M6ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M6ConfigurationExtIEsExtField
				if err := s10.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M7Configuration to APER format.
func (v *M7Configuration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M7Configuration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.M7period, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true); err != nil {
		return fmt.Errorf("encoding m7period: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.M7LinksToLog), 3, true); err != nil {
		return fmt.Errorf("encoding m7-links-to-log: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M7Configuration from APER format.
func (v *M7Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M7Configuration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M7Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M7Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M7Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M7Configuration{}
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
	val_m7period, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "M7period")
	}
	v.M7period = val_m7period
	val_m7linkstolog, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "M7LinksToLog"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M7LinksToLog")
	}
	v.M7LinksToLog = s00.LinksToLog(val_m7linkstolog)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M7ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M7ConfigurationExtIEsExtField
				if err := s10.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MBSFNResultToLogInfo to APER format.
func (v *MBSFNResultToLogInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MBSFNResultToLogInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MBSFNAreaId != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.MBSFNAreaId != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MBSFNAreaId), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
			return fmt.Errorf("encoding mBSFN-AreaId: %w", err)
		}
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.CarrierFreq, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound8, true); err != nil {
		return fmt.Errorf("encoding carrierFreq: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MBSFNResultToLogInfo from APER format.
func (v *MBSFNResultToLogInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNResultToLogInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNResultToLogInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "MBSFNResultToLogInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MBSFNResultToLogInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNResultToLogInfo{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mbsfnareaid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_mbsfnareaid {
		val_mbsfnareaid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MBSFNAreaId")
		}
		if err := aper.ChargeValue(bb, val_mbsfnareaid); err != nil {
			return err
		}
		v.MBSFNAreaId = (*int64)(bb.OwnInt64(int64(val_mbsfnareaid)))

	}
	val_carrierfreq, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound8, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "CarrierFreq")
	}
	v.CarrierFreq = val_carrierfreq
	if opt_ieextensions {
		tmp_ieextensions := make(s10.MBSFNResultToLogInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.MBSFNResultToLogInfoExtIEsExtField
				if err := s10.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes MDTModeExtension to APER format.
func (v *MDTModeExtension) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MDTModeExtension) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes MDTModeExtension from APER format.
func (v *MDTModeExtension) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MDTModeExtension with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MDTModeExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MDTModeExtension")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MDTModeExtension")
	}
	padding, err := aper.CaptureFinalBits(bb, "MDTModeExtension")
	if err != nil {
		return runtime.WrapDecodePath(err, "MDTModeExtension")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MDTModeExtension) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTModeExtension{}
	val_id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(val_id)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	openData_value, err := aper.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MeasurementThresholdA2 to APER format.
func (v *MeasurementThresholdA2) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MeasurementThresholdA2) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "MeasurementThresholdA2:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "MeasurementThresholdA2:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "MeasurementThresholdA2:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "MeasurementThresholdA2:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.MeasurementThresholdA2ChoiceThresholdRSRP:
		if v.ThresholdRSRP == nil {
			return fmt.Errorf("choice alternative threshold-RSRP is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRP), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(97), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRP: %w", err)
		}
	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		if v.ThresholdRSRQ == nil {
			return fmt.Errorf("choice alternative threshold-RSRQ is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRQ), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(34), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRQ: %w", err)
		}
	default:
		return fmt.Errorf("unknown MeasurementThresholdA2 choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MeasurementThresholdA2 from APER format.
func (v *MeasurementThresholdA2) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasurementThresholdA2 with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasurementThresholdA2) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdA2")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdA2")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasurementThresholdA2")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdA2")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MeasurementThresholdA2) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementThresholdA2{}
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
	case s00.MeasurementThresholdA2ChoiceThresholdRSRP:
		val_thresholdrsrp, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(97), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRP")
		}
		tmp_thresholdrsrp := s00.ThresholdRSRP(val_thresholdrsrp)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrp); err != nil {
			return err
		}
		v.ThresholdRSRP = (*s00.ThresholdRSRP)(bb.OwnInt64(int64(tmp_thresholdrsrp)))

	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		val_thresholdrsrq, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(34), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRQ")
		}
		tmp_thresholdrsrq := s00.ThresholdRSRQ(val_thresholdrsrq)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrq); err != nil {
			return err
		}
		v.ThresholdRSRQ = (*s00.ThresholdRSRQ)(bb.OwnInt64(int64(tmp_thresholdrsrq)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MeasurementThresholdL1LoggedMDT to APER format.
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "MeasurementThresholdL1LoggedMDT:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP:
		if v.ThresholdRSRP == nil {
			return fmt.Errorf("choice alternative threshold-RSRP is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRP), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(97), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRP: %w", err)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		if v.ThresholdRSRQ == nil {
			return fmt.Errorf("choice alternative threshold-RSRQ is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRQ), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(34), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRQ: %w", err)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		if v.ChoiceExtensions == nil {
			return fmt.Errorf("choice alternative choice-Extensions is nil")
		}
		if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding choice-Extensions: %w", err)
		}
	default:
		return fmt.Errorf("unknown MeasurementThresholdL1LoggedMDT choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MeasurementThresholdL1LoggedMDT from APER format.
func (v *MeasurementThresholdL1LoggedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasurementThresholdL1LoggedMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasurementThresholdL1LoggedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDT")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasurementThresholdL1LoggedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDT")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MeasurementThresholdL1LoggedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementThresholdL1LoggedMDT{}
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
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRP:
		val_thresholdrsrp, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(97), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRP")
		}
		tmp_thresholdrsrp := s00.ThresholdRSRP(val_thresholdrsrp)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrp); err != nil {
			return err
		}
		v.ThresholdRSRP = (*s00.ThresholdRSRP)(bb.OwnInt64(int64(tmp_thresholdrsrp)))

	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		val_thresholdrsrq, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(34), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRQ")
		}
		tmp_thresholdrsrq := s00.ThresholdRSRQ(val_thresholdrsrq)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrq); err != nil {
			return err
		}
		v.ThresholdRSRQ = (*s00.ThresholdRSRQ)(bb.OwnInt64(int64(tmp_thresholdrsrq)))

	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		var dec_choiceextensions s10.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer
		if err := s10.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MutingPatternInformation to APER format.
func (v *MutingPatternInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MutingPatternInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MutingPatternOffset != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.MutingPatternPeriod), 5, true); err != nil {
		return fmt.Errorf("encoding muting-pattern-period: %w", err)
	}
	if v.MutingPatternOffset != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.MutingPatternOffset, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound4, true); err != nil {
			return fmt.Errorf("encoding muting-pattern-offset: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MutingPatternInformation from APER format.
func (v *MutingPatternInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MutingPatternInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MutingPatternInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "MutingPatternInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MutingPatternInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MutingPatternInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mutingpatternoffset, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_mutingpatternperiod, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MutingPatternPeriod"})
	if err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternPeriod")
	}
	v.MutingPatternPeriod = val_mutingpatternperiod
	if opt_mutingpatternoffset {
		val_mutingpatternoffset, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "MutingPatternOffset")
		}
		v.MutingPatternOffset = val_mutingpatternoffset
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.MutingPatternInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.MutingPatternInformationExtIEsExtField
				if err := s10.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NBIoTPagingEDRXInformation to APER format.
func (v *NBIoTPagingEDRXInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NBIoTPagingEDRXInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.NBIoTPagingTimeWindow != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.NBIoTPagingEDRXCycle), 14, true); err != nil {
		return fmt.Errorf("encoding nB-IoT-paging-eDRX-Cycle: %w", err)
	}
	if v.NBIoTPagingTimeWindow != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.NBIoTPagingTimeWindow), 16, true); err != nil {
			return fmt.Errorf("encoding nB-IoT-pagingTimeWindow: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NBIoTPagingEDRXInformation from APER format.
func (v *NBIoTPagingEDRXInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NBIoTPagingEDRXInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NBIoTPagingEDRXInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "NBIoTPagingEDRXInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NBIoTPagingEDRXInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NBIoTPagingEDRXInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nbiotpagingtimewindow, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nbiotpagingedrxcycle, err := aper.DecodeEnumeratedAligned(bb, 14, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTPagingEDRXCycle"})
	if err != nil {
		return runtime.WrapDecodePath(err, "NBIoTPagingEDRXCycle")
	}
	v.NBIoTPagingEDRXCycle = s00.NBIoTPagingEDRXCycle(val_nbiotpagingedrxcycle)
	if opt_nbiotpagingtimewindow {
		val_nbiotpagingtimewindow, err := aper.DecodeEnumeratedAligned(bb, 16, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTPagingTimeWindow"})
		if err != nil {
			return runtime.WrapDecodePath(err, "NBIoTPagingTimeWindow")
		}
		tmp_nbiotpagingtimewindow := s00.NBIoTPagingTimeWindow(val_nbiotpagingtimewindow)
		if err := aper.ChargeValue(bb, tmp_nbiotpagingtimewindow); err != nil {
			return err
		}
		v.NBIoTPagingTimeWindow = (*s00.NBIoTPagingTimeWindow)(bb.OwnInt64(int64(tmp_nbiotpagingtimewindow)))

	}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NBIoTPagingEDRXInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NBIoTPagingEDRXInformationExtIEsExtField
				if err := s10.BridgeNBIoTPagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NRCGI to APER format.
func (v *NRCGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRCGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("encoding pLMNIdentity: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.NRCellIdentity.Bytes, v.NRCellIdentity.BitLength, 36, 36, true); err != nil {
		return fmt.Errorf("encoding nRCellIdentity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NRCGI from APER format.
func (v *NRCGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NRCGI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NRCGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "NRCGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NRCGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGI{}
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
	bsBytes_nrcellidentity, bsBitLen_nrcellidentity, err := aper.DecodeBitStringAligned(bb, 36, 36, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCellIdentity")
	}
	v.NRCellIdentity = runtime.BitString{Bytes: bsBytes_nrcellidentity, BitLength: bsBitLen_nrcellidentity}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NRCGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRCGIExtIEsExtField
				if err := s10.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NRUESecurityCapabilities to APER format.
func (v *NRUESecurityCapabilities) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRUESecurityCapabilities) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.NRencryptionAlgorithms.Bytes, v.NRencryptionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding nRencryptionAlgorithms: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.NRintegrityProtectionAlgorithms.Bytes, v.NRintegrityProtectionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding nRintegrityProtectionAlgorithms: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NRUESecurityCapabilities from APER format.
func (v *NRUESecurityCapabilities) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NRUESecurityCapabilities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NRUESecurityCapabilities) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
	}
	padding, err := aper.CaptureFinalBits(bb, "NRUESecurityCapabilities")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NRUESecurityCapabilities) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESecurityCapabilities{}
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
	bsBytes_nrencryptionalgorithms, bsBitLen_nrencryptionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRencryptionAlgorithms")
	}
	v.NRencryptionAlgorithms = runtime.BitString{Bytes: bsBytes_nrencryptionalgorithms, BitLength: bsBitLen_nrencryptionalgorithms}
	bsBytes_nrintegrityprotectionalgorithms, bsBitLen_nrintegrityprotectionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRintegrityProtectionAlgorithms")
	}
	v.NRintegrityProtectionAlgorithms = runtime.BitString{Bytes: bsBytes_nrintegrityprotectionalgorithms, BitLength: bsBitLen_nrintegrityprotectionalgorithms}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NRUESecurityCapabilitiesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRUESecurityCapabilitiesExtIEsExtField
				if err := s10.BridgeNRUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NRV2XServicesAuthorized to APER format.
func (v *NRV2XServicesAuthorized) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRV2XServicesAuthorized) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.VehicleUE != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.PedestrianUE != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.VehicleUE != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.VehicleUE), 2, true); err != nil {
			return fmt.Errorf("encoding vehicleUE: %w", err)
		}
	}
	if v.PedestrianUE != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.PedestrianUE), 2, true); err != nil {
			return fmt.Errorf("encoding pedestrianUE: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NRV2XServicesAuthorized from APER format.
func (v *NRV2XServicesAuthorized) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NRV2XServicesAuthorized with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NRV2XServicesAuthorized) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
	}
	padding, err := aper.CaptureFinalBits(bb, "NRV2XServicesAuthorized")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NRV2XServicesAuthorized) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRV2XServicesAuthorized{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_vehicleue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_pedestrianue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_vehicleue {
		val_vehicleue, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "VehicleUE"})
		if err != nil {
			return runtime.WrapDecodePath(err, "VehicleUE")
		}
		tmp_vehicleue := s00.VehicleUE(val_vehicleue)
		if err := aper.ChargeValue(bb, tmp_vehicleue); err != nil {
			return err
		}
		v.VehicleUE = (*s00.VehicleUE)(bb.OwnInt64(int64(tmp_vehicleue)))

	}
	if opt_pedestrianue {
		val_pedestrianue, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PedestrianUE"})
		if err != nil {
			return runtime.WrapDecodePath(err, "PedestrianUE")
		}
		tmp_pedestrianue := s00.PedestrianUE(val_pedestrianue)
		if err := aper.ChargeValue(bb, tmp_pedestrianue); err != nil {
			return err
		}
		v.PedestrianUE = (*s00.PedestrianUE)(bb.OwnInt64(int64(tmp_pedestrianue)))

	}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NRV2XServicesAuthorizedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRV2XServicesAuthorizedExtIEsExtField
				if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NRUESidelinkAggregateMaximumBitrate to APER format.
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.UEaggregateMaximumBitRate), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uEaggregateMaximumBitRate: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NRUESidelinkAggregateMaximumBitrate from APER format.
func (v *NRUESidelinkAggregateMaximumBitrate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NRUESidelinkAggregateMaximumBitrate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NRUESidelinkAggregateMaximumBitrate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
	}
	padding, err := aper.CaptureFinalBits(bb, "NRUESidelinkAggregateMaximumBitrate")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NRUESidelinkAggregateMaximumBitrate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRUESidelinkAggregateMaximumBitrate{}
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
	val_ueaggregatemaximumbitrate, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEaggregateMaximumBitRate")
	}
	v.UEaggregateMaximumBitRate = s00.BitRate(val_ueaggregatemaximumbitrate)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
				if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes OverloadResponse to APER format.
func (v *OverloadResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *OverloadResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "OverloadResponse:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "OverloadResponse:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "OverloadResponse:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "OverloadResponse:", v.Choice)
	}
	switch v.Choice {
	case s00.OverloadResponseChoiceOverloadAction:
		if v.OverloadAction == nil {
			return fmt.Errorf("choice alternative overloadAction is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.OverloadAction), 3, true); err != nil {
			return fmt.Errorf("encoding overloadAction: %w", err)
		}
	default:
		return fmt.Errorf("unknown OverloadResponse choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes OverloadResponse from APER format.
func (v *OverloadResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OverloadResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OverloadResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OverloadResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OverloadResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "OverloadResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "OverloadResponse")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *OverloadResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OverloadResponse{}
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
	case s00.OverloadResponseChoiceOverloadAction:
		val_overloadaction, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 4, Path: "OverloadAction"})
		if err != nil {
			return runtime.WrapDecodePath(err, "OverloadAction")
		}
		tmp_overloadaction := s00.OverloadAction(val_overloadaction)
		if err := aper.ChargeValue(bb, tmp_overloadaction); err != nil {
			return err
		}
		v.OverloadAction = (*s00.OverloadAction)(bb.OwnInt64(int64(tmp_overloadaction)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes PC5FlowBitRates to APER format.
func (v *PC5FlowBitRates) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PC5FlowBitRates) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.GuaranteedFlowBitRate), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding guaranteedFlowBitRate: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.MaximumFlowBitRate), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding maximumFlowBitRate: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PC5FlowBitRates from APER format.
func (v *PC5FlowBitRates) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PC5FlowBitRates with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PC5FlowBitRates) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PC5FlowBitRates")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PC5FlowBitRates")
	}
	padding, err := aper.CaptureFinalBits(bb, "PC5FlowBitRates")
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5FlowBitRates")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PC5FlowBitRates) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5FlowBitRates{}
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
	val_guaranteedflowbitrate, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "GuaranteedFlowBitRate")
	}
	v.GuaranteedFlowBitRate = s00.BitRate(val_guaranteedflowbitrate)
	val_maximumflowbitrate, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MaximumFlowBitRate")
	}
	v.MaximumFlowBitRate = s00.BitRate(val_maximumflowbitrate)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.PC5FlowBitRatesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PC5FlowBitRatesExtIEsExtField
				if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes GlobalRANNODEID to APER format.
func (v *GlobalRANNODEID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *GlobalRANNODEID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "GlobalRANNODEID:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "GlobalRANNODEID:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "GlobalRANNODEID:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "GlobalRANNODEID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.GlobalRANNODEIDChoiceGNB:
		if v.GNB == nil {
			return fmt.Errorf("choice alternative gNB is nil")
		}
		if err := s18.BridgeGNBMethodMarshalAPERTo(v.GNB, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding gNB: %w", err)
		}
	case s00.GlobalRANNODEIDChoiceNgENB:
		if v.NgENB == nil {
			return fmt.Errorf("choice alternative ng-eNB is nil")
		}
		if err := v.NgENB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding ng-eNB: %w", err)
		}
	default:
		return fmt.Errorf("unknown GlobalRANNODEID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes GlobalRANNODEID from APER format.
func (v *GlobalRANNODEID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes GlobalRANNODEID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *GlobalRANNODEID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	padding, err := aper.CaptureFinalBits(bb, "GlobalRANNODEID")
	if err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *GlobalRANNODEID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GlobalRANNODEID{}
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
	case s00.GlobalRANNODEIDChoiceGNB:
		toleranceMark_gnb := bb.EnterComponent("GNB")
		var dec_gnb s18.GNB
		if err := s18.BridgeGNBMethodUnmarshalAPERFrom(&dec_gnb, bb); err != nil {
			return runtime.WrapDecodePath(err, "GNB")
		}
		if err := aper.ChargeValue(bb, dec_gnb); err != nil {
			return err
		}
		v.GNB = &dec_gnb
		bb.LeaveComponent(toleranceMark_gnb)
	case s00.GlobalRANNODEIDChoiceNgENB:
		toleranceMark_ngenb := bb.EnterComponent("NgENB")
		var dec_ngenb NGENB
		if err := dec_ngenb.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NgENB")
		}
		if err := aper.ChargeValue(bb, dec_ngenb); err != nil {
			return err
		}
		v.NgENB = &dec_ngenb
		bb.LeaveComponent(toleranceMark_ngenb)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes NGENB to APER format.
func (v *NGENB) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NGENB) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeGlobalENBIDMethodMarshalAPERTo(&v.GlobalNgENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-ng-eNB-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeNGENBExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NGENB from APER format.
func (v *NGENB) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NGENB with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NGENB) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NGENB")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NGENB")
	}
	padding, err := aper.CaptureFinalBits(bb, "NGENB")
	if err != nil {
		return runtime.WrapDecodePath(err, "NGENB")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NGENB) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NGENB{}
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
	toleranceMark_globalngenbid := bb.EnterComponent("GlobalNgENBID")
	if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&v.GlobalNgENBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalNgENBID")
	}
	bb.LeaveComponent(toleranceMark_globalngenbid)
	if opt_ieextensions {
		tmp_ieextensions := make(s10.NGENBExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NGENBExtIEsExtField
				if err := s10.BridgeNGENBExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M1ThresholdEventA2 to APER format.
func (v *M1ThresholdEventA2) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M1ThresholdEventA2) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := v.MeasurementThreshold.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding measurementThreshold: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M1ThresholdEventA2 from APER format.
func (v *M1ThresholdEventA2) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes M1ThresholdEventA2 with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *M1ThresholdEventA2) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	padding, err := aper.CaptureFinalBits(bb, "M1ThresholdEventA2")
	if err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *M1ThresholdEventA2) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1ThresholdEventA2{}
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
	if err := v.MeasurementThreshold.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThreshold")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s10.M1ThresholdEventA2ExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.M1ThresholdEventA2ExtIEsExtField
				if err := s10.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ContextatSource) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ContextatSource", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ContextatSource", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ContextatSource) WithoutReplay() ContextatSource {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ContextatSource
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EventL1LoggedMDTConfig) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventL1LoggedMDTConfig", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EventL1LoggedMDTConfig", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EventL1LoggedMDTConfig) WithoutReplay() EventL1LoggedMDTConfig {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EventL1LoggedMDTConfig
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EventTrigger) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventTrigger", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EventTrigger", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EventTrigger) WithoutReplay() EventTrigger {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EventTrigger
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *GlobalRANNODEID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "GlobalRANNODEID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "GlobalRANNODEID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v GlobalRANNODEID) WithoutReplay() GlobalRANNODEID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero GlobalRANNODEID
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LoggedMDTTrigger) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LoggedMDTTrigger", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LoggedMDTTrigger", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LoggedMDTTrigger) WithoutReplay() LoggedMDTTrigger {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LoggedMDTTrigger
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M1ThresholdEventA2) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M1ThresholdEventA2", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M1ThresholdEventA2", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M1ThresholdEventA2) WithoutReplay() M1ThresholdEventA2 {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M1ThresholdEventA2
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M3Configuration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M3Configuration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M3Configuration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M3Configuration) WithoutReplay() M3Configuration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M3Configuration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M4Configuration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M4Configuration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M4Configuration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M4Configuration) WithoutReplay() M4Configuration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M4Configuration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M5Configuration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M5Configuration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M5Configuration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M5Configuration) WithoutReplay() M5Configuration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M5Configuration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M6Configuration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M6Configuration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M6Configuration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M6Configuration) WithoutReplay() M6Configuration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M6Configuration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M7Configuration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "M7Configuration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M7Configuration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M7Configuration) WithoutReplay() M7Configuration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M7Configuration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNResultToLogInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNResultToLogInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MBSFNResultToLogInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNResultToLogInfo) WithoutReplay() MBSFNResultToLogInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MBSFNResultToLogInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MDTModeExtension) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MDTModeExtension", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MDTModeExtension", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MDTModeExtension) WithoutReplay() MDTModeExtension {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MDTModeExtension
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementThresholdA2) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementThresholdA2", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MeasurementThresholdA2", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementThresholdA2) WithoutReplay() MeasurementThresholdA2 {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MeasurementThresholdA2
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementThresholdL1LoggedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementThresholdL1LoggedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MeasurementThresholdL1LoggedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementThresholdL1LoggedMDT) WithoutReplay() MeasurementThresholdL1LoggedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MeasurementThresholdL1LoggedMDT
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MutingPatternInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MutingPatternInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MutingPatternInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MutingPatternInformation) WithoutReplay() MutingPatternInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MutingPatternInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NBIoTPagingEDRXInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NBIoTPagingEDRXInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NBIoTPagingEDRXInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NBIoTPagingEDRXInformation) WithoutReplay() NBIoTPagingEDRXInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NBIoTPagingEDRXInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NGENB) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NGENB", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NGENB", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NGENB) WithoutReplay() NGENB {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NGENB
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRCGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRCGI", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NRCGI", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRCGI) WithoutReplay() NRCGI {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NRCGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRUESecurityCapabilities) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRUESecurityCapabilities", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NRUESecurityCapabilities", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRUESecurityCapabilities) WithoutReplay() NRUESecurityCapabilities {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NRUESecurityCapabilities
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRUESidelinkAggregateMaximumBitrate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRUESidelinkAggregateMaximumBitrate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NRUESidelinkAggregateMaximumBitrate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRUESidelinkAggregateMaximumBitrate) WithoutReplay() NRUESidelinkAggregateMaximumBitrate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NRUESidelinkAggregateMaximumBitrate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRV2XServicesAuthorized) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRV2XServicesAuthorized", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NRV2XServicesAuthorized", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRV2XServicesAuthorized) WithoutReplay() NRV2XServicesAuthorized {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NRV2XServicesAuthorized
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OverloadResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "OverloadResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "OverloadResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OverloadResponse) WithoutReplay() OverloadResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero OverloadResponse
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PC5FlowBitRates) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PC5FlowBitRates", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PC5FlowBitRates", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PC5FlowBitRates) WithoutReplay() PC5FlowBitRates {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PC5FlowBitRates
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ContextatSource) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ContextatSource) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ContextatSource.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ContextatSource.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ContextatSource) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ContextatSource.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ContextatSource.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EventL1LoggedMDTConfig) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EventL1LoggedMDTConfig) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventL1LoggedMDTConfig.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventL1LoggedMDTConfig.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EventL1LoggedMDTConfig) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EventL1LoggedMDTConfig.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EventL1LoggedMDTConfig.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M1ThresholdEventA2) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M1ThresholdEventA2) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M1ThresholdEventA2.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M1ThresholdEventA2.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M1ThresholdEventA2) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M1ThresholdEventA2.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M1ThresholdEventA2.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M3Configuration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M3Configuration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M3Configuration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M3Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M3Configuration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M3Configuration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M3Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M4Configuration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M4Configuration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M4Configuration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M4Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M4Configuration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M4Configuration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M4Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M5Configuration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M5Configuration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M5Configuration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M5Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M5Configuration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M5Configuration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M5Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M6Configuration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M6Configuration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M6Configuration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M6Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M6Configuration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M6Configuration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M6Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *M7Configuration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M7Configuration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M7Configuration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M7Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M7Configuration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M7Configuration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M7Configuration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MBSFNResultToLogInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MBSFNResultToLogInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MBSFNResultToLogInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNResultToLogInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MBSFNResultToLogInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MBSFNResultToLogInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNResultToLogInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MutingPatternInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MutingPatternInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MutingPatternInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MutingPatternInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MutingPatternInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MutingPatternInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MutingPatternInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NBIoTPagingEDRXInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NBIoTPagingEDRXInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NBIoTPagingEDRXInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NBIoTPagingEDRXInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NBIoTPagingEDRXInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NBIoTPagingEDRXInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NBIoTPagingEDRXInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NGENB) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NGENB) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NGENB.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NGENB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NGENB) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NGENB.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NGENB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRCGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRCGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRCGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRUESecurityCapabilities) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRUESecurityCapabilities) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRUESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRUESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRUESecurityCapabilities) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRUESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRUESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRUESidelinkAggregateMaximumBitrate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRUESidelinkAggregateMaximumBitrate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRUESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRUESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRUESidelinkAggregateMaximumBitrate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRUESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRUESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRV2XServicesAuthorized) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRV2XServicesAuthorized) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRV2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRV2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRV2XServicesAuthorized) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRV2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRV2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PC5FlowBitRates) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PC5FlowBitRates) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5FlowBitRates.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5FlowBitRates.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PC5FlowBitRates) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5FlowBitRates.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5FlowBitRates.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ContextatSource) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ContextatSource")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ContextatSource) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ContextatSource")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APContextatSource(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ContextatSource")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ContextatSource")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ContextatSource) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ContextatSource")
}
func (v *ContextatSource) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ContextatSource")
}
func (v *ContextatSource) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APContextatSource(v, &s)
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
func (v *ContextatSource) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ContextatSource) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EventL1LoggedMDTConfig) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EventL1LoggedMDTConfig")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EventL1LoggedMDTConfig) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EventL1LoggedMDTConfig")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEventL1LoggedMDTConfig(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EventL1LoggedMDTConfig")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EventL1LoggedMDTConfig")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EventL1LoggedMDTConfig) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EventL1LoggedMDTConfig")
}
func (v *EventL1LoggedMDTConfig) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EventL1LoggedMDTConfig")
}
func (v *EventL1LoggedMDTConfig) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEventL1LoggedMDTConfig(v, &s)
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
func (v *EventL1LoggedMDTConfig) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EventL1LoggedMDTConfig) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EventTrigger) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EventTrigger")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EventTrigger) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EventTrigger")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEventTrigger(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EventTrigger")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EventTrigger")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EventTrigger) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EventTrigger")
}
func (v *EventTrigger) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EventTrigger")
}
func (v *EventTrigger) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEventTrigger(v, &s)
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
func (v *EventTrigger) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EventTrigger) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *GlobalRANNODEID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "GlobalRANNODEID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *GlobalRANNODEID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "GlobalRANNODEID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APGlobalRANNODEID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "GlobalRANNODEID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "GlobalRANNODEID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *GlobalRANNODEID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "GlobalRANNODEID")
}
func (v *GlobalRANNODEID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "GlobalRANNODEID")
}
func (v *GlobalRANNODEID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APGlobalRANNODEID(v, &s)
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
func (v *GlobalRANNODEID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *GlobalRANNODEID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LoggedMDTTrigger) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LoggedMDTTrigger")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LoggedMDTTrigger) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LoggedMDTTrigger")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLoggedMDTTrigger(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LoggedMDTTrigger")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LoggedMDTTrigger")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LoggedMDTTrigger) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LoggedMDTTrigger")
}
func (v *LoggedMDTTrigger) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LoggedMDTTrigger")
}
func (v *LoggedMDTTrigger) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLoggedMDTTrigger(v, &s)
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
func (v *LoggedMDTTrigger) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LoggedMDTTrigger) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M1ThresholdEventA2) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M1ThresholdEventA2")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M1ThresholdEventA2) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M1ThresholdEventA2")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM1ThresholdEventA2(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M1ThresholdEventA2")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M1ThresholdEventA2")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M1ThresholdEventA2) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M1ThresholdEventA2")
}
func (v *M1ThresholdEventA2) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M1ThresholdEventA2")
}
func (v *M1ThresholdEventA2) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM1ThresholdEventA2(v, &s)
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
func (v *M1ThresholdEventA2) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M1ThresholdEventA2) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M3Configuration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M3Configuration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M3Configuration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M3Configuration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM3Configuration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M3Configuration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M3Configuration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M3Configuration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M3Configuration")
}
func (v *M3Configuration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M3Configuration")
}
func (v *M3Configuration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM3Configuration(v, &s)
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
func (v *M3Configuration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M3Configuration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M4Configuration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M4Configuration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M4Configuration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M4Configuration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM4Configuration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M4Configuration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M4Configuration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M4Configuration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M4Configuration")
}
func (v *M4Configuration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M4Configuration")
}
func (v *M4Configuration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM4Configuration(v, &s)
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
func (v *M4Configuration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M4Configuration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M5Configuration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M5Configuration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M5Configuration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M5Configuration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM5Configuration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M5Configuration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M5Configuration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M5Configuration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M5Configuration")
}
func (v *M5Configuration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M5Configuration")
}
func (v *M5Configuration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM5Configuration(v, &s)
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
func (v *M5Configuration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M5Configuration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M6Configuration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M6Configuration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M6Configuration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M6Configuration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM6Configuration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M6Configuration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M6Configuration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M6Configuration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M6Configuration")
}
func (v *M6Configuration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M6Configuration")
}
func (v *M6Configuration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM6Configuration(v, &s)
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
func (v *M6Configuration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M6Configuration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M7Configuration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M7Configuration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M7Configuration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M7Configuration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM7Configuration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M7Configuration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M7Configuration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M7Configuration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M7Configuration")
}
func (v *M7Configuration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M7Configuration")
}
func (v *M7Configuration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM7Configuration(v, &s)
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
func (v *M7Configuration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M7Configuration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MBSFNResultToLogInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MBSFNResultToLogInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MBSFNResultToLogInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MBSFNResultToLogInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMBSFNResultToLogInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MBSFNResultToLogInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MBSFNResultToLogInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MBSFNResultToLogInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MBSFNResultToLogInfo")
}
func (v *MBSFNResultToLogInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MBSFNResultToLogInfo")
}
func (v *MBSFNResultToLogInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMBSFNResultToLogInfo(v, &s)
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
func (v *MBSFNResultToLogInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MBSFNResultToLogInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MDTModeExtension) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MDTModeExtension")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MDTModeExtension) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MDTModeExtension")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMDTModeExtension(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MDTModeExtension")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MDTModeExtension")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MDTModeExtension) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MDTModeExtension")
}
func (v *MDTModeExtension) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MDTModeExtension")
}
func (v *MDTModeExtension) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMDTModeExtension(v, &s)
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
func (v *MDTModeExtension) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MDTModeExtension) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MeasurementThresholdA2) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MeasurementThresholdA2")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MeasurementThresholdA2) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasurementThresholdA2")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMeasurementThresholdA2(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MeasurementThresholdA2")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MeasurementThresholdA2")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MeasurementThresholdA2) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MeasurementThresholdA2")
}
func (v *MeasurementThresholdA2) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MeasurementThresholdA2")
}
func (v *MeasurementThresholdA2) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMeasurementThresholdA2(v, &s)
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
func (v *MeasurementThresholdA2) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MeasurementThresholdA2) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MeasurementThresholdL1LoggedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MeasurementThresholdL1LoggedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasurementThresholdL1LoggedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMeasurementThresholdL1LoggedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MeasurementThresholdL1LoggedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MeasurementThresholdL1LoggedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MeasurementThresholdL1LoggedMDT")
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MeasurementThresholdL1LoggedMDT")
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMeasurementThresholdL1LoggedMDT(v, &s)
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
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MeasurementThresholdL1LoggedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MutingPatternInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MutingPatternInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MutingPatternInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MutingPatternInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMutingPatternInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MutingPatternInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MutingPatternInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MutingPatternInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MutingPatternInformation")
}
func (v *MutingPatternInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MutingPatternInformation")
}
func (v *MutingPatternInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMutingPatternInformation(v, &s)
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
func (v *MutingPatternInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MutingPatternInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NBIoTPagingEDRXInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NBIoTPagingEDRXInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NBIoTPagingEDRXInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NBIoTPagingEDRXInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNBIoTPagingEDRXInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NBIoTPagingEDRXInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NBIoTPagingEDRXInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NBIoTPagingEDRXInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NBIoTPagingEDRXInformation")
}
func (v *NBIoTPagingEDRXInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NBIoTPagingEDRXInformation")
}
func (v *NBIoTPagingEDRXInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNBIoTPagingEDRXInformation(v, &s)
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
func (v *NBIoTPagingEDRXInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NBIoTPagingEDRXInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NGENB) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NGENB")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NGENB) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NGENB")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNGENB(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NGENB")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NGENB")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NGENB) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NGENB")
}
func (v *NGENB) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NGENB")
}
func (v *NGENB) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNGENB(v, &s)
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
func (v *NGENB) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NGENB) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NRCGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NRCGI")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NRCGI) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NRCGI")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNRCGI(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NRCGI")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NRCGI")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NRCGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NRCGI")
}
func (v *NRCGI) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NRCGI")
}
func (v *NRCGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNRCGI(v, &s)
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
func (v *NRCGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NRCGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NRUESecurityCapabilities) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NRUESecurityCapabilities")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NRUESecurityCapabilities) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NRUESecurityCapabilities")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNRUESecurityCapabilities(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NRUESecurityCapabilities")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NRUESecurityCapabilities")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NRUESecurityCapabilities) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NRUESecurityCapabilities")
}
func (v *NRUESecurityCapabilities) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NRUESecurityCapabilities")
}
func (v *NRUESecurityCapabilities) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNRUESecurityCapabilities(v, &s)
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
func (v *NRUESecurityCapabilities) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NRUESecurityCapabilities) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NRUESidelinkAggregateMaximumBitrate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NRUESidelinkAggregateMaximumBitrate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NRUESidelinkAggregateMaximumBitrate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NRUESidelinkAggregateMaximumBitrate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NRUESidelinkAggregateMaximumBitrate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NRUESidelinkAggregateMaximumBitrate")
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NRUESidelinkAggregateMaximumBitrate")
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v, &s)
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
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NRUESidelinkAggregateMaximumBitrate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NRV2XServicesAuthorized) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NRV2XServicesAuthorized")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NRV2XServicesAuthorized) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NRV2XServicesAuthorized")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNRV2XServicesAuthorized(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NRV2XServicesAuthorized")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NRV2XServicesAuthorized")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NRV2XServicesAuthorized) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NRV2XServicesAuthorized")
}
func (v *NRV2XServicesAuthorized) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NRV2XServicesAuthorized")
}
func (v *NRV2XServicesAuthorized) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNRV2XServicesAuthorized(v, &s)
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
func (v *NRV2XServicesAuthorized) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NRV2XServicesAuthorized) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *OverloadResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "OverloadResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *OverloadResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OverloadResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APOverloadResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "OverloadResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "OverloadResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *OverloadResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "OverloadResponse")
}
func (v *OverloadResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "OverloadResponse")
}
func (v *OverloadResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APOverloadResponse(v, &s)
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
func (v *OverloadResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *OverloadResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PC5FlowBitRates) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PC5FlowBitRates")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PC5FlowBitRates) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PC5FlowBitRates")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPC5FlowBitRates(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PC5FlowBitRates")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PC5FlowBitRates")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PC5FlowBitRates) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PC5FlowBitRates")
}
func (v *PC5FlowBitRates) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PC5FlowBitRates")
}
func (v *PC5FlowBitRates) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPC5FlowBitRates(v, &s)
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
func (v *PC5FlowBitRates) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PC5FlowBitRates) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ContextatSource) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ContextatSource")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ContextatSource
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APContextatSource(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ContextatSource{}
		return report, aper.OperationError(err, "ContextatSource")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ContextatSource")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EventL1LoggedMDTConfig) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EventL1LoggedMDTConfig")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EventL1LoggedMDTConfig
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEventL1LoggedMDTConfig(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EventL1LoggedMDTConfig{}
		return report, aper.OperationError(err, "EventL1LoggedMDTConfig")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EventL1LoggedMDTConfig")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EventTrigger) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EventTrigger")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EventTrigger
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEventTrigger(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EventTrigger{}
		return report, aper.OperationError(err, "EventTrigger")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EventTrigger")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *GlobalRANNODEID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "GlobalRANNODEID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded GlobalRANNODEID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APGlobalRANNODEID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = GlobalRANNODEID{}
		return report, aper.OperationError(err, "GlobalRANNODEID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "GlobalRANNODEID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LoggedMDTTrigger) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LoggedMDTTrigger")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LoggedMDTTrigger
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLoggedMDTTrigger(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LoggedMDTTrigger{}
		return report, aper.OperationError(err, "LoggedMDTTrigger")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LoggedMDTTrigger")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M1ThresholdEventA2) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M1ThresholdEventA2")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M1ThresholdEventA2
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM1ThresholdEventA2(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M1ThresholdEventA2{}
		return report, aper.OperationError(err, "M1ThresholdEventA2")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M1ThresholdEventA2")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M3Configuration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M3Configuration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M3Configuration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM3Configuration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M3Configuration{}
		return report, aper.OperationError(err, "M3Configuration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M3Configuration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M4Configuration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M4Configuration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M4Configuration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM4Configuration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M4Configuration{}
		return report, aper.OperationError(err, "M4Configuration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M4Configuration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M5Configuration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M5Configuration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M5Configuration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM5Configuration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M5Configuration{}
		return report, aper.OperationError(err, "M5Configuration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M5Configuration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M6Configuration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M6Configuration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M6Configuration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM6Configuration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M6Configuration{}
		return report, aper.OperationError(err, "M6Configuration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M6Configuration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *M7Configuration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M7Configuration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M7Configuration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM7Configuration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M7Configuration{}
		return report, aper.OperationError(err, "M7Configuration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M7Configuration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MBSFNResultToLogInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MBSFNResultToLogInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MBSFNResultToLogInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMBSFNResultToLogInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MBSFNResultToLogInfo{}
		return report, aper.OperationError(err, "MBSFNResultToLogInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MBSFNResultToLogInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MDTModeExtension) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MDTModeExtension")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MDTModeExtension
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMDTModeExtension(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MDTModeExtension{}
		return report, aper.OperationError(err, "MDTModeExtension")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MDTModeExtension")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MeasurementThresholdA2) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasurementThresholdA2")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MeasurementThresholdA2
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMeasurementThresholdA2(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MeasurementThresholdA2{}
		return report, aper.OperationError(err, "MeasurementThresholdA2")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasurementThresholdA2")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MeasurementThresholdL1LoggedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasurementThresholdL1LoggedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MeasurementThresholdL1LoggedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMeasurementThresholdL1LoggedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MeasurementThresholdL1LoggedMDT{}
		return report, aper.OperationError(err, "MeasurementThresholdL1LoggedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasurementThresholdL1LoggedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MutingPatternInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MutingPatternInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MutingPatternInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMutingPatternInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MutingPatternInformation{}
		return report, aper.OperationError(err, "MutingPatternInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MutingPatternInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NBIoTPagingEDRXInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NBIoTPagingEDRXInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NBIoTPagingEDRXInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNBIoTPagingEDRXInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NBIoTPagingEDRXInformation{}
		return report, aper.OperationError(err, "NBIoTPagingEDRXInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NBIoTPagingEDRXInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NGENB) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NGENB")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NGENB
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNGENB(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NGENB{}
		return report, aper.OperationError(err, "NGENB")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NGENB")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NRCGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NRCGI")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NRCGI
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNRCGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NRCGI{}
		return report, aper.OperationError(err, "NRCGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NRCGI")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NRUESecurityCapabilities) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NRUESecurityCapabilities")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NRUESecurityCapabilities
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNRUESecurityCapabilities(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NRUESecurityCapabilities{}
		return report, aper.OperationError(err, "NRUESecurityCapabilities")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NRUESecurityCapabilities")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NRUESidelinkAggregateMaximumBitrate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NRUESidelinkAggregateMaximumBitrate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NRUESidelinkAggregateMaximumBitrate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NRUESidelinkAggregateMaximumBitrate{}
		return report, aper.OperationError(err, "NRUESidelinkAggregateMaximumBitrate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NRUESidelinkAggregateMaximumBitrate")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NRV2XServicesAuthorized) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NRV2XServicesAuthorized")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NRV2XServicesAuthorized
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNRV2XServicesAuthorized(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NRV2XServicesAuthorized{}
		return report, aper.OperationError(err, "NRV2XServicesAuthorized")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NRV2XServicesAuthorized")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *OverloadResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OverloadResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded OverloadResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APOverloadResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = OverloadResponse{}
		return report, aper.OperationError(err, "OverloadResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OverloadResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PC5FlowBitRates) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PC5FlowBitRates")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PC5FlowBitRates
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPC5FlowBitRates(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PC5FlowBitRates{}
		return report, aper.OperationError(err, "PC5FlowBitRates")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PC5FlowBitRates")
}

// NewCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewCauseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s14.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	value := s14.Cause{UnknownExtension: &extension}
	if _, err := s14.BridgeCauseMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s14.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	return value, aper.OperationError(nil, "CauseUnknownExtension")
}

// NewDLCOUNTPDCPSNlengthUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewDLCOUNTPDCPSNlengthUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s14.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	value := s14.DLCOUNTPDCPSNlength{UnknownExtension: &extension}
	if _, err := s14.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s14.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	return value, aper.OperationError(nil, "DLCOUNTPDCPSNlengthUnknownExtension")
}

// NewDLDiscardingUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewDLDiscardingUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s15.DLDiscarding, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingUnknownExtension")
	}
	value := s15.DLDiscarding{UnknownExtension: &extension}
	if _, err := s15.BridgeDLDiscardingMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s15.DLDiscarding{}, aper.OperationError(err, "DLDiscardingUnknownExtension")
	}
	return value, aper.OperationError(nil, "DLDiscardingUnknownExtension")
}

// NewENBIDUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewENBIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s15.ENBID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDUnknownExtension")
	}
	value := s15.ENBID{UnknownExtension: &extension}
	if _, err := s15.BridgeENBIDMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s15.ENBID{}, aper.OperationError(err, "ENBIDUnknownExtension")
	}
	return value, aper.OperationError(nil, "ENBIDUnknownExtension")
}

// NewGNBIdentityUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewGNBIdentityUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s18.GNBIdentity, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityUnknownExtension")
	}
	value := s18.GNBIdentity{UnknownExtension: &extension}
	if _, err := s18.BridgeGNBIdentityMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s18.GNBIdentity{}, aper.OperationError(err, "GNBIdentityUnknownExtension")
	}
	return value, aper.OperationError(nil, "GNBIdentityUnknownExtension")
}

// NewGlobalRANNODEIDUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewGlobalRANNODEIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	value := GlobalRANNODEID{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	return value, aper.OperationError(nil, "GlobalRANNODEIDUnknownExtension")
}

// NewLastVisitedGERANCellInformationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewLastVisitedGERANCellInformationUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s18.LastVisitedGERANCellInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUnknownExtension")
	}
	value := s18.LastVisitedGERANCellInformation{UnknownExtension: &extension}
	if _, err := s18.BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s18.LastVisitedGERANCellInformation{}, aper.OperationError(err, "LastVisitedGERANCellInformationUnknownExtension")
	}
	return value, aper.OperationError(nil, "LastVisitedGERANCellInformationUnknownExtension")
}

// NewLoggedMDTTriggerUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewLoggedMDTTriggerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	value := LoggedMDTTrigger{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerUnknownExtension")
}

// NewMeasurementThresholdA2UnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMeasurementThresholdA2UnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	value := MeasurementThresholdA2{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	return value, aper.OperationError(nil, "MeasurementThresholdA2UnknownExtension")
}

// NewOverloadResponseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewOverloadResponseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (OverloadResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return OverloadResponse{}, aper.OperationError(err, "OverloadResponseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return OverloadResponse{}, aper.OperationError(err, "OverloadResponseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return OverloadResponse{}, aper.OperationError(err, "OverloadResponseUnknownExtension")
	}
	value := OverloadResponse{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return OverloadResponse{}, aper.OperationError(err, "OverloadResponseUnknownExtension")
	}
	return value, aper.OperationError(nil, "OverloadResponseUnknownExtension")
}

// NASDeliveryIndication represents the ASN.1 type NASDeliveryIndication (SEQUENCE).
type NASDeliveryIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s10.NASDeliveryIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMECPRelocationIndication represents the ASN.1 type MMECPRelocationIndication (SEQUENCE).
type MMECPRelocationIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s10.MMECPRelocationIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes NASDeliveryIndication to APER format.
func (v *NASDeliveryIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NASDeliveryIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s10.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NASDeliveryIndication from APER format.
func (v *NASDeliveryIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NASDeliveryIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NASDeliveryIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "NASDeliveryIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NASDeliveryIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASDeliveryIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s10.NASDeliveryIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.NASDeliveryIndicationIEField
			if err := s10.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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

// MarshalAPER encodes MMECPRelocationIndication to APER format.
func (v *MMECPRelocationIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMECPRelocationIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMECPRelocationIndication from APER format.
func (v *MMECPRelocationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMECPRelocationIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMECPRelocationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMECPRelocationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMECPRelocationIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s10.MMECPRelocationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.MMECPRelocationIndicationIEField
			if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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
func (v *MMECPRelocationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMECPRelocationIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMECPRelocationIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMECPRelocationIndication) WithoutReplay() MMECPRelocationIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMECPRelocationIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NASDeliveryIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NASDeliveryIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NASDeliveryIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NASDeliveryIndication) WithoutReplay() NASDeliveryIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NASDeliveryIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *MMECPRelocationIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMECPRelocationIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMECPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMECPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMECPRelocationIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMECPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMECPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NASDeliveryIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NASDeliveryIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NASDeliveryIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NASDeliveryIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NASDeliveryIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NASDeliveryIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NASDeliveryIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MMECPRelocationIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMECPRelocationIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMECPRelocationIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMECPRelocationIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMECPRelocationIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMECPRelocationIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMECPRelocationIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMECPRelocationIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMECPRelocationIndication")
}
func (v *MMECPRelocationIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMECPRelocationIndication")
}
func (v *MMECPRelocationIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMECPRelocationIndication(v, &s)
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
func (v *MMECPRelocationIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMECPRelocationIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NASDeliveryIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NASDeliveryIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NASDeliveryIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NASDeliveryIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNASDeliveryIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NASDeliveryIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NASDeliveryIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NASDeliveryIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NASDeliveryIndication")
}
func (v *NASDeliveryIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NASDeliveryIndication")
}
func (v *NASDeliveryIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNASDeliveryIndication(v, &s)
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
func (v *NASDeliveryIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NASDeliveryIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMECPRelocationIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMECPRelocationIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMECPRelocationIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMECPRelocationIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMECPRelocationIndication{}
		return report, aper.OperationError(err, "MMECPRelocationIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMECPRelocationIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NASDeliveryIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NASDeliveryIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NASDeliveryIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNASDeliveryIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NASDeliveryIndication{}
		return report, aper.OperationError(err, "NASDeliveryIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NASDeliveryIndication")
}

type MultiCellLoadReportingResponse = []MultiCellLoadReportingResponseItem

// MultiCellLoadReportingResponseItem represents the ASN.1 CHOICE type MultiCellLoadReportingResponse-Item.
type MultiCellLoadReportingResponseItem struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding                           `json:"-"`
	perOpenTypePadding aper.CompletePadding                           `json:"-"`
	UnknownExtension   *aper.ChoiceExtension                          `json:"UnknownExtension,omitempty"`
	EUTRANResponse     *s17.EUTRANResponse                            `json:"EUTRANResponse,omitempty"`
	UTRANResponse      []byte                                         `json:"UTRANResponse,omitzero"`
	GERANResponse      []byte                                         `json:"GERANResponse,omitzero"`
	EHRPD              *s15.EHRPDMultiSectorLoadReportingResponseItem `json:"EHRPD,omitempty"`
}
type NotificationCellList = []NotificationCellListItem

// NotificationCellListItem represents the ASN.1 type NotificationCellList-Item (SEQUENCE).
type NotificationCellListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           []byte                 `asn1:"tag:0,context,implicit"`
	NotifyFlag       s00.NotifyFlag         `asn1:"tag:1,context,implicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes MultiCellLoadReportingResponseItem to APER format.
func (v *MultiCellLoadReportingResponseItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "MultiCellLoadReportingResponseItem:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "MultiCellLoadReportingResponseItem:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "MultiCellLoadReportingResponseItem:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "MultiCellLoadReportingResponseItem:", v.Choice)
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
		case s00.MultiCellLoadReportingResponseItemChoiceEHRPD:
			if v.EHRPD == nil {
				return fmt.Errorf("choice alternative eHRPD is nil")
			}
			if err := s15.BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERTo(v.EHRPD, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown MultiCellLoadReportingResponseItem extension choice %d", v.Choice)
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
	case s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		if v.EUTRANResponse == nil {
			return fmt.Errorf("choice alternative eUTRANResponse is nil")
		}
		if err := s17.BridgeEUTRANResponseMethodMarshalAPERTo(v.EUTRANResponse, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding eUTRANResponse: %w", err)
		}
	case s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		if err := aper.EncodeOctetStringAligned(bb, v.UTRANResponse, 0, 0, false); err != nil {
			return fmt.Errorf("encoding uTRANResponse: %w", err)
		}
	case s00.MultiCellLoadReportingResponseItemChoiceGERANResponse:
		if err := aper.EncodeOctetStringAligned(bb, v.GERANResponse, 0, 0, false); err != nil {
			return fmt.Errorf("encoding gERANResponse: %w", err)
		}
	default:
		return fmt.Errorf("unknown MultiCellLoadReportingResponseItem choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MultiCellLoadReportingResponseItem from APER format.
func (v *MultiCellLoadReportingResponseItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MultiCellLoadReportingResponseItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MultiCellLoadReportingResponseItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "MultiCellLoadReportingResponseItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MultiCellLoadReportingResponseItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MultiCellLoadReportingResponseItem{}
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
		case s00.MultiCellLoadReportingResponseItemChoiceEHRPD:
			extensionPath = "EHRPD"
			recoveryMark_ehrpd := inner.RecoveryComponent("EHRPD")
			var dec_ehrpd s15.EHRPDMultiSectorLoadReportingResponseItem
			if err := s15.BridgeEHRPDMultiSectorLoadReportingResponseItemMethodUnmarshalAPERFrom(&dec_ehrpd, inner); err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			if err := aper.ChargeValue(inner, dec_ehrpd); err != nil {
				return err
			}
			v.EHRPD = &dec_ehrpd
			inner.LeaveComponent(recoveryMark_ehrpd)
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
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
	case s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		toleranceMark_eutranresponse := bb.EnterComponent("EUTRANResponse")
		var dec_eutranresponse s17.EUTRANResponse
		if err := s17.BridgeEUTRANResponseMethodUnmarshalAPERFrom(&dec_eutranresponse, bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANResponse")
		}
		if err := aper.ChargeValue(bb, dec_eutranresponse); err != nil {
			return err
		}
		v.EUTRANResponse = &dec_eutranresponse
		bb.LeaveComponent(toleranceMark_eutranresponse)
	case s00.MultiCellLoadReportingResponseItemChoiceUTRANResponse:
		val_utranresponse, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRANResponse")
		}
		tmp_utranresponse := val_utranresponse
		v.UTRANResponse = tmp_utranresponse
	case s00.MultiCellLoadReportingResponseItemChoiceGERANResponse:
		val_geranresponse, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "GERANResponse")
		}
		tmp_geranresponse := val_geranresponse
		v.GERANResponse = tmp_geranresponse
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes NotificationCellListItem to APER format.
func (v *NotificationCellListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NotificationCellListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, v.CellID, 0, 0, false); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.NotifyFlag), 2, true); err != nil {
		return fmt.Errorf("encoding notifyFlag: %w", err)
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

// UnmarshalAPER decodes NotificationCellListItem from APER format.
func (v *NotificationCellListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NotificationCellListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NotificationCellListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "NotificationCellListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NotificationCellListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NotificationCellListItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_cellid, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	v.CellID = val_cellid
	val_notifyflag, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NotifyFlag"})
	if err != nil {
		return runtime.WrapDecodePath(err, "NotifyFlag")
	}
	v.NotifyFlag = s00.NotifyFlag(val_notifyflag)
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
func (v *MultiCellLoadReportingResponseItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MultiCellLoadReportingResponseItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MultiCellLoadReportingResponseItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MultiCellLoadReportingResponseItem) WithoutReplay() MultiCellLoadReportingResponseItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MultiCellLoadReportingResponseItem
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NotificationCellListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NotificationCellListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NotificationCellListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NotificationCellListItem) WithoutReplay() NotificationCellListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NotificationCellListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *NotificationCellListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NotificationCellListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NotificationCellListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NotificationCellListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NotificationCellListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NotificationCellListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NotificationCellListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MultiCellLoadReportingResponseItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MultiCellLoadReportingResponseItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingResponseItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMultiCellLoadReportingResponseItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MultiCellLoadReportingResponseItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MultiCellLoadReportingResponseItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MultiCellLoadReportingResponseItem")
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MultiCellLoadReportingResponseItem")
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMultiCellLoadReportingResponseItem(v, &s)
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
func (v *MultiCellLoadReportingResponseItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MultiCellLoadReportingResponseItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *NotificationCellListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NotificationCellListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NotificationCellListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NotificationCellListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNotificationCellListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NotificationCellListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NotificationCellListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NotificationCellListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NotificationCellListItem")
}
func (v *NotificationCellListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NotificationCellListItem")
}
func (v *NotificationCellListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNotificationCellListItem(v, &s)
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
func (v *NotificationCellListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NotificationCellListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MultiCellLoadReportingResponseItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingResponseItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MultiCellLoadReportingResponseItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMultiCellLoadReportingResponseItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MultiCellLoadReportingResponseItem{}
		return report, aper.OperationError(err, "MultiCellLoadReportingResponseItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MultiCellLoadReportingResponseItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NotificationCellListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NotificationCellListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NotificationCellListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNotificationCellListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NotificationCellListItem{}
		return report, aper.OperationError(err, "NotificationCellListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NotificationCellListItem")
}

// NewCellLoadReportingResponseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewCellLoadReportingResponseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s17.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	value := s17.CellLoadReportingResponse{UnknownExtension: &extension}
	if _, err := s17.BridgeCellLoadReportingResponseMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s17.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	return value, aper.OperationError(nil, "CellLoadReportingResponseUnknownExtension")
}

// NewIRATCellIDUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewIRATCellIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s18.IRATCellID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUnknownExtension")
	}
	value := s18.IRATCellID{UnknownExtension: &extension}
	if _, err := s18.BridgeIRATCellIDMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s18.IRATCellID{}, aper.OperationError(err, "IRATCellIDUnknownExtension")
	}
	return value, aper.OperationError(nil, "IRATCellIDUnknownExtension")
}

// NewMultiCellLoadReportingResponseItemUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMultiCellLoadReportingResponseItemUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	value := MultiCellLoadReportingResponseItem{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemUnknownExtension")
}

type NASNonDeliveryIndicationIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowNASPDU      *s00.NASPDU
	rowCause       *s14.Cause
}

func (v NASNonDeliveryIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of NASNonDeliveryIndicationIEValue and reports whether the opaque alternative is selected.
func (v *NASNonDeliveryIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (NASNonDeliveryIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs"}}
}
func (NASNonDeliveryIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(26):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of NASNonDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASNonDeliveryIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of NASNonDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASNonDeliveryIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsNASPDU returns the selected NASPDU value of NASNonDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASNonDeliveryIndicationIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}

// AsCause returns the selected Cause value of NASNonDeliveryIndicationIEValue and reports whether that alternative is active.
func (v *NASNonDeliveryIndicationIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v NASNonDeliveryIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (NASNonDeliveryIndicationIEValue, error) {
	out := NASNonDeliveryIndicationIEValue{id: id}
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
func (v NASNonDeliveryIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v NASNonDeliveryIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "NASNonDeliveryIndication-IEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "NASNonDeliveryIndication-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(26):
		if v.rowNASPDU == nil {
			return nil, fmt.Errorf("%s missing value", "NASNonDeliveryIndication-IEs.id-NAS-PDU:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "NASNonDeliveryIndication-IEs.id-Cause:")
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
		return nil, fmt.Errorf("%s id %d has no value", "NASNonDeliveryIndicationIEValue:", v.id)
	}
}

type NASNonDeliveryIndicationIETable struct{}

func NASNonDeliveryIndicationIEs() NASNonDeliveryIndicationIETable {
	return NASNonDeliveryIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of NASNonDeliveryIndicationIETable.
func (NASNonDeliveryIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by NASNonDeliveryIndicationIETable.
func (NASNonDeliveryIndicationIETable) Table() s00.NASNonDeliveryIndicationIEValueIETable {
	return func() s00.NASNonDeliveryIndicationIEValueIETable {
		sealed := s00.NASNonDeliveryIndicationIEValueIETable{}
		*s00.BridgeNASNonDeliveryIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (NASNonDeliveryIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: NASNonDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of NASNonDeliveryIndicationIETable.
func (t NASNonDeliveryIndicationIETable) MMEUES1APID() NASNonDeliveryIndicationMMEUES1APIDIEBinding {
	return NASNonDeliveryIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero NASNonDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding NASNonDeliveryIndication-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) NASNonDeliveryIndicationIEValue {
			return NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *NASNonDeliveryIndicationIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (NASNonDeliveryIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: NASNonDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of NASNonDeliveryIndicationIETable.
func (t NASNonDeliveryIndicationIETable) ENBUES1APID() NASNonDeliveryIndicationENBUES1APIDIEBinding {
	return NASNonDeliveryIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero NASNonDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding NASNonDeliveryIndication-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) NASNonDeliveryIndicationIEValue {
			return NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *NASNonDeliveryIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (NASNonDeliveryIndicationIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: NASNonDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs", Row: "id-NAS-PDU"}}}
}

// NASPDU returns the typed binding for the NASPDU row of NASNonDeliveryIndicationIETable.
func (t NASNonDeliveryIndicationIETable) NASPDU() NASNonDeliveryIndicationNASPDUIEBinding {
	return NASNonDeliveryIndicationNASPDUIEBinding{info: t.infoNASPDU(), codec: func() s01.NASPDUValueCodec {
		sealed := s01.NASPDUValueCodec{}
		*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
		*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			var zero NASNonDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(26), raw)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			value, ok := decoded.AsNASPDU()
			if !ok {
				var empty s00.NASPDU
				return empty, fmt.Errorf("binding NASNonDeliveryIndication-IEs.id-NAS-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.NASPDU) NASNonDeliveryIndicationIEValue {
			return NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}
		}, get: func(value *NASNonDeliveryIndicationIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }}
}
func (NASNonDeliveryIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: NASNonDeliveryIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "NASNonDeliveryIndication-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of NASNonDeliveryIndicationIETable.
func (t NASNonDeliveryIndicationIETable) Cause() NASNonDeliveryIndicationCauseIEBinding {
	return NASNonDeliveryIndicationCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero NASNonDeliveryIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding NASNonDeliveryIndication-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) NASNonDeliveryIndicationIEValue {
			return NASNonDeliveryIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *NASNonDeliveryIndicationIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in NASNonDeliveryIndicationIETable.
func (t NASNonDeliveryIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (NASNonDeliveryIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return NASNonDeliveryIndicationIEField{Id: id, Criticality: criticality, Value: NASNonDeliveryIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// EventL1LoggedMDTConfigCodec binds the complete source value type.
func EventL1LoggedMDTConfigCodec() EventL1LoggedMDTConfigValueCodec {
	return EventL1LoggedMDTConfigValueCodec{path: "EventL1LoggedMDTConfig", decode: func(data []byte, options aper.DecodeState) (EventL1LoggedMDTConfig, error) {
		var value EventL1LoggedMDTConfig
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EventL1LoggedMDTConfig{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EventL1LoggedMDTConfig, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EventL1LoggedMDTConfig, options aper.DecodeState) (EventL1LoggedMDTConfig, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEventL1LoggedMDTConfig(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EventL1LoggedMDTConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEventL1LoggedMDTConfig(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EventL1LoggedMDTConfig"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// EventTriggerCodec binds the complete source value type.
func EventTriggerCodec() EventTriggerValueCodec {
	return EventTriggerValueCodec{path: "EventTrigger", decode: func(data []byte, options aper.DecodeState) (EventTrigger, error) {
		var value EventTrigger
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EventTrigger{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EventTrigger, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EventTrigger, options aper.DecodeState) (EventTrigger, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEventTrigger(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EventTrigger, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APEventTrigger(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EventTrigger"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// M1PeriodicReportingCodec binds the complete source value type.
func M1PeriodicReportingCodec() s18.M1PeriodicReportingValueCodec {
	return func() s18.M1PeriodicReportingValueCodec {
		sealed := s18.M1PeriodicReportingValueCodec{}
		*s18.BridgeM1PeriodicReportingValueCodecFieldPath(&sealed) = "M1PeriodicReporting"
		*s18.BridgeM1PeriodicReportingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.M1PeriodicReporting, error) {
			var value s18.M1PeriodicReporting
			if err := s18.BridgeM1PeriodicReportingMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
				return s18.M1PeriodicReporting{}, err
			}
			*s18.BridgeM1PeriodicReportingFieldReceived(&value) = true
			*s18.BridgeM1PeriodicReportingFieldReceivedAbsolute(&value) = true
			*s18.BridgeM1PeriodicReportingFieldReceivedBytes(&value) = aper.OriginalWire(data)
			return value, nil
		}
		*s18.BridgeM1PeriodicReportingValueCodecFieldEncode(&sealed) = func(value s18.M1PeriodicReporting, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s18.BridgeM1PeriodicReportingMethodMarshalAPERBudget((&value), budget, fresh)
		}
		*s18.BridgeM1PeriodicReportingValueCodecFieldCapture(&sealed) = func(v s18.M1PeriodicReporting, options aper.DecodeState) (s18.M1PeriodicReporting, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APM1PeriodicReporting(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeM1PeriodicReportingValueCodecFieldCompare(&sealed) = func(v s18.M1PeriodicReporting, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APM1PeriodicReporting(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeM1PeriodicReportingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M1PeriodicReporting"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M1ThresholdEventA2Codec binds the complete source value type.
func M1ThresholdEventA2Codec() M1ThresholdEventA2ValueCodec {
	return M1ThresholdEventA2ValueCodec{path: "M1ThresholdEventA2", decode: func(data []byte, options aper.DecodeState) (M1ThresholdEventA2, error) {
		var value M1ThresholdEventA2
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return M1ThresholdEventA2{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value M1ThresholdEventA2, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v M1ThresholdEventA2, options aper.DecodeState) (M1ThresholdEventA2, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APM1ThresholdEventA2(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,

			root
	}, compare: func(v M1ThresholdEventA2, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APM1ThresholdEventA2(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M1ThresholdEventA2"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MBSFNResultToLogInfoCodec binds the complete source value type.
func MBSFNResultToLogInfoCodec() MBSFNResultToLogInfoValueCodec {
	return MBSFNResultToLogInfoValueCodec{path: "MBSFNResultToLogInfo", decode: func(data []byte, options aper.DecodeState) (MBSFNResultToLogInfo, error) {
		var value MBSFNResultToLogInfo
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MBSFNResultToLogInfo{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MBSFNResultToLogInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MBSFNResultToLogInfo, options aper.DecodeState) (MBSFNResultToLogInfo, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMBSFNResultToLogInfo(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MBSFNResultToLogInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMBSFNResultToLogInfo(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNResultToLogInfo"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MDTModeExtensionCodec binds the complete source value type.
func MDTModeExtensionCodec() MDTModeExtensionValueCodec {
	return MDTModeExtensionValueCodec{path: "MDTModeExtension", decode: func(data []byte, options aper.DecodeState) (MDTModeExtension, error) {
		var value MDTModeExtension
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MDTModeExtension{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MDTModeExtension, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MDTModeExtension, options aper.DecodeState) (MDTModeExtension, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APMDTModeExtension(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MDTModeExtension, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMDTModeExtension(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTModeExtension"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MMEUES1APIDCodec binds the complete APER value type.
func MMEUES1APIDCodec() s01.MMEUES1APIDValueCodec {
	return s17.CellTrafficTraceIEs().MMEUES1APID().Codec()
}

// MeasurementThresholdA2Codec binds the complete source value type.
func MeasurementThresholdA2Codec() MeasurementThresholdA2ValueCodec {
	return MeasurementThresholdA2ValueCodec{path: "MeasurementThresholdA2", decode: func(data []byte, options aper.DecodeState) (MeasurementThresholdA2, error) {
		var value MeasurementThresholdA2
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MeasurementThresholdA2{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MeasurementThresholdA2, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MeasurementThresholdA2, options aper.DecodeState) (MeasurementThresholdA2, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMeasurementThresholdA2(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MeasurementThresholdA2, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMeasurementThresholdA2(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementThresholdA2"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MeasurementThresholdL1LoggedMDTCodec binds the complete source value type.
func MeasurementThresholdL1LoggedMDTCodec() MeasurementThresholdL1LoggedMDTValueCodec {
	return MeasurementThresholdL1LoggedMDTValueCodec{path: "MeasurementThresholdL1LoggedMDT", decode: func(data []byte, options aper.DecodeState) (MeasurementThresholdL1LoggedMDT, error) {
		var value MeasurementThresholdL1LoggedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MeasurementThresholdL1LoggedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MeasurementThresholdL1LoggedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MeasurementThresholdL1LoggedMDT, options aper.DecodeState) (MeasurementThresholdL1LoggedMDT, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMeasurementThresholdL1LoggedMDT(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MeasurementThresholdL1LoggedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMeasurementThresholdL1LoggedMDT(&v, &s)

		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementThresholdL1LoggedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// MultiCellLoadReportingResponseItemCodec binds the complete source value type.
func MultiCellLoadReportingResponseItemCodec() MultiCellLoadReportingResponseItemValueCodec {
	return MultiCellLoadReportingResponseItemValueCodec{path: "MultiCellLoadReportingResponseItem", decode: func(data []byte, options aper.DecodeState) (MultiCellLoadReportingResponseItem, error) {
		var value MultiCellLoadReportingResponseItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MultiCellLoadReportingResponseItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MultiCellLoadReportingResponseItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MultiCellLoadReportingResponseItem, options aper.DecodeState) (MultiCellLoadReportingResponseItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMultiCellLoadReportingResponseItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MultiCellLoadReportingResponseItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APMultiCellLoadReportingResponseItem(
			&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MultiCellLoadReportingResponseItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// NGENBCodec binds the complete source value type.
func NGENBCodec() NGENBValueCodec {
	return NGENBValueCodec{path: "NGENB", decode: func(data []byte, options aper.DecodeState) (NGENB, error) {
		var value NGENB
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NGENB{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NGENB, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NGENB, options aper.DecodeState) (NGENB, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APNGENB(&v, &s)
		var root aper.Snapshot
		s.End(f,
			&root, false)
		return v, root
	}, compare: func(v NGENB, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APNGENB(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NGENB"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// NRCGICodec binds the complete source value type.
func NRCGICodec() NRCGIValueCodec {
	return NRCGIValueCodec{path: "NRCGI", decode: func(data []byte, options aper.DecodeState) (NRCGI, error) {
		var value NRCGI
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NRCGI{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NRCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NRCGI, options aper.DecodeState) (NRCGI, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APNRCGI(&v, &s)
		var root aper.Snapshot
		s.End(f,
			&root, false)
		return v, root
	}, compare: func(v NRCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APNRCGI(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRCGI"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// NotificationCellListItemCodec binds the complete source value type.
func NotificationCellListItemCodec() NotificationCellListItemValueCodec {
	return NotificationCellListItemValueCodec{path: "NotificationCellListItem", decode: func(data []byte, options aper.DecodeState) (NotificationCellListItem, error) {
		var value NotificationCellListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NotificationCellListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NotificationCellListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NotificationCellListItem, options aper.DecodeState) (NotificationCellListItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APNotificationCellListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NotificationCellListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APNotificationCellListItem(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NotificationCellListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PC5FlowBitRatesCodec binds the complete source value type.
func PC5FlowBitRatesCodec() PC5FlowBitRatesValueCodec {
	return PC5FlowBitRatesValueCodec{path: "PC5FlowBitRates", decode: func(data []byte, options aper.DecodeState) (PC5FlowBitRates, error) {
		var value PC5FlowBitRates
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PC5FlowBitRates{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PC5FlowBitRates, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PC5FlowBitRates, options aper.DecodeState) (PC5FlowBitRates, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APPC5FlowBitRates(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PC5FlowBitRates, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPC5FlowBitRates(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5FlowBitRates"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeContextatSourceAPERValueFieldContext(v *ContextatSourceAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeContextatSourceAPERValueFieldReceived(v *ContextatSourceAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeContextatSourceAPERValueFieldReplay(v *ContextatSourceAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeContextatSourceAPERValueFieldWithoutReplay(v *ContextatSourceAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeContextatSourceFieldExtCount(v *ContextatSource) *int64   { return &v.extCount }
func BridgeContextatSourceFieldExtData(v *ContextatSource) *[][]byte { return &v.extData }
func BridgeContextatSourceFieldExtOrigin(v *ContextatSource) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeContextatSourceFieldExtPresent(v *ContextatSource) *[]bool       { return &v.extPresent }
func BridgeContextatSourceFieldExtWire(v *ContextatSource) *[]aper.WireSpan { return &v.extWire }
func BridgeContextatSourceFieldIEExtensionsIndef(v *ContextatSource) *bool {
	return &v.iEExtensionsIndef
}
func BridgeContextatSourceFieldPerExtPadding(v *ContextatSource) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeContextatSourceFieldPerPadding(v *ContextatSource) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeContextatSourceFieldReceived(v *ContextatSource) *bool         { return &v.received }
func BridgeContextatSourceFieldReceivedAbsolute(v *ContextatSource) *bool { return &v.receivedAbsolute }
func BridgeContextatSourceFieldReceivedBytes(v *ContextatSource) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeContextatSourceFieldReceivedLocation(v *ContextatSource) *aper.Location {
	return &v.receivedLocation
}
func BridgeContextatSourceFieldReplay(v *ContextatSource) *aper.Snapshot { return &v.replay }
func BridgeContextatSourceFieldStream(v *ContextatSource) *aper.WireSpan { return &v.stream }
func BridgeContextatSourceFieldWithoutReplay(v *ContextatSource) *bool   { return &v.withoutReplay }
func BridgeContextatSourceMethodMarshalAPERBudget(v *ContextatSource, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeContextatSourceMethodMarshalAPERBudgetValue(v *ContextatSource, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeContextatSourceMethodMarshalAPERChanged(v *ContextatSource, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeContextatSourceMethodMarshalAPERChangedValue(v *ContextatSource, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeContextatSourceMethodMarshalAPERLegacy(v *ContextatSource) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeContextatSourceMethodMarshalAPERNewValue(v *ContextatSource, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeContextatSourceMethodMarshalAPERPlanned(v *ContextatSource, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeContextatSourceMethodMarshalAPERTo(v *ContextatSource, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeContextatSourceMethodUnmarshalAPERFrom(v *ContextatSource, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeContextatSourceMethodUnmarshalAPERLegacy(v *ContextatSource, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeContextatSourceMethodUnmarshalAPERWithOptions(v *ContextatSource, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeContextatSourceValueCodecFieldCapture(v *ContextatSourceValueCodec) *func(ContextatSource, aper.DecodeState) (ContextatSource, aper.Snapshot) {
	return &v.capture
}
func BridgeContextatSourceValueCodecFieldCompare(v *ContextatSourceValueCodec) *func(ContextatSource, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeContextatSourceValueCodecFieldContext(v *ContextatSourceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeContextatSourceValueCodecFieldDecode(v *ContextatSourceValueCodec) *func([]byte, aper.DecodeState) (ContextatSource, error) {
	return &v.decode
}
func BridgeContextatSourceValueCodecFieldEncode(v *ContextatSourceValueCodec) *func(ContextatSource, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeContextatSourceValueCodecFieldPath(v *ContextatSourceValueCodec) *aper.Path {
	return &v.path
}
func BridgeContextatSourceValueCodecMethodEncodeBudgetValue(v ContextatSourceValueCodec, a0 ContextatSource, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeContextatSourceValueCodecMethodEncodeChanged(v ContextatSourceValueCodec, a0 ContextatSource, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEventL1LoggedMDTConfigAPERValueFieldContext(v *EventL1LoggedMDTConfigAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventL1LoggedMDTConfigAPERValueFieldReceived(v *EventL1LoggedMDTConfigAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEventL1LoggedMDTConfigAPERValueFieldReplay(v *EventL1LoggedMDTConfigAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEventL1LoggedMDTConfigAPERValueFieldWithoutReplay(v *EventL1LoggedMDTConfigAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEventL1LoggedMDTConfigFieldExtCount(v *EventL1LoggedMDTConfig) *int64   { return &v.extCount }
func BridgeEventL1LoggedMDTConfigFieldExtData(v *EventL1LoggedMDTConfig) *[][]byte { return &v.extData }
func BridgeEventL1LoggedMDTConfigFieldExtOrigin(v *EventL1LoggedMDTConfig) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEventL1LoggedMDTConfigFieldExtPresent(v *EventL1LoggedMDTConfig) *[]bool {
	return &v.extPresent
}
func BridgeEventL1LoggedMDTConfigFieldExtWire(v *EventL1LoggedMDTConfig) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEventL1LoggedMDTConfigFieldIEExtensionsIndef(v *EventL1LoggedMDTConfig) *bool {
	return &v.iEExtensionsIndef
}
func BridgeEventL1LoggedMDTConfigFieldPerExtPadding(v *EventL1LoggedMDTConfig) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEventL1LoggedMDTConfigFieldPerPadding(v *EventL1LoggedMDTConfig) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEventL1LoggedMDTConfigFieldReceived(v *EventL1LoggedMDTConfig) *bool { return &v.received }
func BridgeEventL1LoggedMDTConfigFieldReceivedAbsolute(v *EventL1LoggedMDTConfig) *bool {
	return &v.receivedAbsolute
}
func BridgeEventL1LoggedMDTConfigFieldReceivedBytes(v *EventL1LoggedMDTConfig) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEventL1LoggedMDTConfigFieldReceivedLocation(v *EventL1LoggedMDTConfig) *aper.Location {
	return &v.receivedLocation
}
func BridgeEventL1LoggedMDTConfigFieldReplay(v *EventL1LoggedMDTConfig) *aper.Snapshot {
	return &v.replay
}
func BridgeEventL1LoggedMDTConfigFieldStream(v *EventL1LoggedMDTConfig) *aper.WireSpan {
	return &v.stream
}
func BridgeEventL1LoggedMDTConfigFieldWithoutReplay(v *EventL1LoggedMDTConfig) *bool {
	return &v.withoutReplay
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERBudget(v *EventL1LoggedMDTConfig, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERBudgetValue(v *EventL1LoggedMDTConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERChanged(v *EventL1LoggedMDTConfig, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERChangedValue(v *EventL1LoggedMDTConfig, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERLegacy(v *EventL1LoggedMDTConfig) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERNewValue(v *EventL1LoggedMDTConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERPlanned(v *EventL1LoggedMDTConfig, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEventL1LoggedMDTConfigMethodMarshalAPERTo(v *EventL1LoggedMDTConfig, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventL1LoggedMDTConfigMethodUnmarshalAPERFrom(v *EventL1LoggedMDTConfig, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventL1LoggedMDTConfigMethodUnmarshalAPERLegacy(v *EventL1LoggedMDTConfig, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEventL1LoggedMDTConfigMethodUnmarshalAPERWithOptions(v *EventL1LoggedMDTConfig, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldCapture(v *EventL1LoggedMDTConfigValueCodec) *func(EventL1LoggedMDTConfig, aper.DecodeState) (EventL1LoggedMDTConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldCompare(v *EventL1LoggedMDTConfigValueCodec) *func(EventL1LoggedMDTConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldContext(v *EventL1LoggedMDTConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldDecode(v *EventL1LoggedMDTConfigValueCodec) *func([]byte, aper.DecodeState) (EventL1LoggedMDTConfig, error) {
	return &v.decode
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldEncode(v *EventL1LoggedMDTConfigValueCodec) *func(EventL1LoggedMDTConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventL1LoggedMDTConfigValueCodecFieldPath(v *EventL1LoggedMDTConfigValueCodec) *aper.Path {
	return &v.path
}
func BridgeEventL1LoggedMDTConfigValueCodecMethodEncodeBudgetValue(v EventL1LoggedMDTConfigValueCodec, a0 EventL1LoggedMDTConfig, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEventL1LoggedMDTConfigValueCodecMethodEncodeChanged(v EventL1LoggedMDTConfigValueCodec, a0 EventL1LoggedMDTConfig, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEventTriggerAPERValueFieldContext(v *EventTriggerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerAPERValueFieldReceived(v *EventTriggerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEventTriggerAPERValueFieldReplay(v *EventTriggerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeEventTriggerAPERValueFieldWithoutReplay(v *EventTriggerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEventTriggerFieldPerOpenTypePadding(v *EventTrigger) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeEventTriggerFieldPerPadding(v *EventTrigger) *aper.CompletePadding { return &v.perPadding }
func BridgeEventTriggerFieldReceived(v *EventTrigger) *bool                   { return &v.received }
func BridgeEventTriggerFieldReceivedAbsolute(v *EventTrigger) *bool           { return &v.receivedAbsolute }
func BridgeEventTriggerFieldReceivedBytes(v *EventTrigger) *aper.WireSpan     { return &v.receivedBytes }
func BridgeEventTriggerFieldReceivedLocation(v *EventTrigger) *aper.Location {
	return &v.receivedLocation
}
func BridgeEventTriggerFieldReplay(v *EventTrigger) *aper.Snapshot { return &v.replay }
func BridgeEventTriggerFieldStream(v *EventTrigger) *aper.WireSpan { return &v.stream }
func BridgeEventTriggerFieldWithoutReplay(v *EventTrigger) *bool   { return &v.withoutReplay }
func BridgeEventTriggerMethodMarshalAPERBudget(v *EventTrigger, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEventTriggerMethodMarshalAPERBudgetValue(v *EventTrigger, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeEventTriggerMethodMarshalAPERChanged(v *EventTrigger, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEventTriggerMethodMarshalAPERChangedValue(v *EventTrigger, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEventTriggerMethodMarshalAPERLegacy(v *EventTrigger) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEventTriggerMethodMarshalAPERNewValue(v *EventTrigger, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeEventTriggerMethodMarshalAPERPlanned(v *EventTrigger, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeEventTriggerMethodMarshalAPERTo(v *EventTrigger, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEventTriggerMethodUnmarshalAPERFrom(v *EventTrigger, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEventTriggerMethodUnmarshalAPERLegacy(v *EventTrigger, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEventTriggerMethodUnmarshalAPERWithOptions(v *EventTrigger, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEventTriggerValueCodecFieldCapture(v *EventTriggerValueCodec) *func(EventTrigger, aper.DecodeState) (EventTrigger, aper.Snapshot) {
	return &v.capture
}
func BridgeEventTriggerValueCodecFieldCompare(v *EventTriggerValueCodec) *func(EventTrigger, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEventTriggerValueCodecFieldContext(v *EventTriggerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEventTriggerValueCodecFieldDecode(v *EventTriggerValueCodec) *func([]byte, aper.DecodeState) (EventTrigger, error) {
	return &v.decode
}
func BridgeEventTriggerValueCodecFieldEncode(v *EventTriggerValueCodec) *func(EventTrigger, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEventTriggerValueCodecFieldPath(v *EventTriggerValueCodec) *aper.Path { return &v.path }
func BridgeEventTriggerValueCodecMethodEncodeBudgetValue(v EventTriggerValueCodec, a0 EventTrigger, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeEventTriggerValueCodecMethodEncodeChanged(v EventTriggerValueCodec, a0 EventTrigger, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeGlobalRANNODEIDAPERValueFieldContext(v *GlobalRANNODEIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalRANNODEIDAPERValueFieldReceived(v *GlobalRANNODEIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeGlobalRANNODEIDAPERValueFieldReplay(v *GlobalRANNODEIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeGlobalRANNODEIDAPERValueFieldWithoutReplay(v *GlobalRANNODEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeGlobalRANNODEIDFieldPerOpenTypePadding(v *GlobalRANNODEID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeGlobalRANNODEIDFieldPerPadding(v *GlobalRANNODEID) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeGlobalRANNODEIDFieldReceived(v *GlobalRANNODEID) *bool         { return &v.received }
func BridgeGlobalRANNODEIDFieldReceivedAbsolute(v *GlobalRANNODEID) *bool { return &v.receivedAbsolute }
func BridgeGlobalRANNODEIDFieldReceivedBytes(v *GlobalRANNODEID) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeGlobalRANNODEIDFieldReceivedLocation(v *GlobalRANNODEID) *aper.Location {
	return &v.receivedLocation
}
func BridgeGlobalRANNODEIDFieldReplay(v *GlobalRANNODEID) *aper.Snapshot { return &v.replay }
func BridgeGlobalRANNODEIDFieldStream(v *GlobalRANNODEID) *aper.WireSpan { return &v.stream }
func BridgeGlobalRANNODEIDFieldWithoutReplay(v *GlobalRANNODEID) *bool   { return &v.withoutReplay }
func BridgeGlobalRANNODEIDMethodMarshalAPERBudget(v *GlobalRANNODEID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERBudgetValue(v *GlobalRANNODEID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERChanged(v *GlobalRANNODEID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERChangedValue(v *GlobalRANNODEID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERLegacy(v *GlobalRANNODEID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeGlobalRANNODEIDMethodMarshalAPERNewValue(v *GlobalRANNODEID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERPlanned(v *GlobalRANNODEID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeGlobalRANNODEIDMethodMarshalAPERTo(v *GlobalRANNODEID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(v *GlobalRANNODEID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeGlobalRANNODEIDMethodUnmarshalAPERLegacy(v *GlobalRANNODEID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeGlobalRANNODEIDMethodUnmarshalAPERWithOptions(v *GlobalRANNODEID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeGlobalRANNODEIDValueCodecFieldCapture(v *GlobalRANNODEIDValueCodec) *func(GlobalRANNODEID, aper.DecodeState) (GlobalRANNODEID, aper.Snapshot) {
	return &v.capture
}
func BridgeGlobalRANNODEIDValueCodecFieldCompare(v *GlobalRANNODEIDValueCodec) *func(GlobalRANNODEID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGlobalRANNODEIDValueCodecFieldContext(v *GlobalRANNODEIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGlobalRANNODEIDValueCodecFieldDecode(v *GlobalRANNODEIDValueCodec) *func([]byte, aper.DecodeState) (GlobalRANNODEID, error) {
	return &v.decode
}
func BridgeGlobalRANNODEIDValueCodecFieldEncode(v *GlobalRANNODEIDValueCodec) *func(GlobalRANNODEID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGlobalRANNODEIDValueCodecFieldPath(v *GlobalRANNODEIDValueCodec) *aper.Path {
	return &v.path
}
func BridgeGlobalRANNODEIDValueCodecMethodEncodeBudgetValue(v GlobalRANNODEIDValueCodec, a0 GlobalRANNODEID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeGlobalRANNODEIDValueCodecMethodEncodeChanged(v GlobalRANNODEIDValueCodec, a0 GlobalRANNODEID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLoggedMDTTriggerAPERValueFieldContext(v *LoggedMDTTriggerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTTriggerAPERValueFieldReceived(v *LoggedMDTTriggerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLoggedMDTTriggerAPERValueFieldReplay(v *LoggedMDTTriggerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLoggedMDTTriggerAPERValueFieldWithoutReplay(v *LoggedMDTTriggerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLoggedMDTTriggerFieldPerOpenTypePadding(v *LoggedMDTTrigger) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeLoggedMDTTriggerFieldPerPadding(v *LoggedMDTTrigger) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeLoggedMDTTriggerFieldReceived(v *LoggedMDTTrigger) *bool { return &v.received }
func BridgeLoggedMDTTriggerFieldReceivedAbsolute(v *LoggedMDTTrigger) *bool {
	return &v.receivedAbsolute
}
func BridgeLoggedMDTTriggerFieldReceivedBytes(v *LoggedMDTTrigger) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLoggedMDTTriggerFieldReceivedLocation(v *LoggedMDTTrigger) *aper.Location {
	return &v.receivedLocation
}
func BridgeLoggedMDTTriggerFieldReplay(v *LoggedMDTTrigger) *aper.Snapshot { return &v.replay }
func BridgeLoggedMDTTriggerFieldStream(v *LoggedMDTTrigger) *aper.WireSpan { return &v.stream }
func BridgeLoggedMDTTriggerFieldWithoutReplay(v *LoggedMDTTrigger) *bool   { return &v.withoutReplay }
func BridgeLoggedMDTTriggerMethodMarshalAPERBudget(v *LoggedMDTTrigger, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERBudgetValue(v *LoggedMDTTrigger, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERChanged(v *LoggedMDTTrigger, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERChangedValue(v *LoggedMDTTrigger, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERLegacy(v *LoggedMDTTrigger) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLoggedMDTTriggerMethodMarshalAPERNewValue(v *LoggedMDTTrigger, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERPlanned(v *LoggedMDTTrigger, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLoggedMDTTriggerMethodMarshalAPERTo(v *LoggedMDTTrigger, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLoggedMDTTriggerMethodUnmarshalAPERFrom(v *LoggedMDTTrigger, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLoggedMDTTriggerMethodUnmarshalAPERLegacy(v *LoggedMDTTrigger, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLoggedMDTTriggerMethodUnmarshalAPERWithOptions(v *LoggedMDTTrigger, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLoggedMDTTriggerValueCodecFieldCapture(v *LoggedMDTTriggerValueCodec) *func(LoggedMDTTrigger, aper.DecodeState) (LoggedMDTTrigger, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggedMDTTriggerValueCodecFieldCompare(v *LoggedMDTTriggerValueCodec) *func(LoggedMDTTrigger, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggedMDTTriggerValueCodecFieldContext(v *LoggedMDTTriggerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggedMDTTriggerValueCodecFieldDecode(v *LoggedMDTTriggerValueCodec) *func([]byte, aper.DecodeState) (LoggedMDTTrigger, error) {
	return &v.decode
}
func BridgeLoggedMDTTriggerValueCodecFieldEncode(v *LoggedMDTTriggerValueCodec) *func(LoggedMDTTrigger, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggedMDTTriggerValueCodecFieldPath(v *LoggedMDTTriggerValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMDTTriggerValueCodecMethodEncodeBudgetValue(v LoggedMDTTriggerValueCodec, a0 LoggedMDTTrigger, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLoggedMDTTriggerValueCodecMethodEncodeChanged(v LoggedMDTTriggerValueCodec, a0 LoggedMDTTrigger, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM1ThresholdEventA2APERValueFieldContext(v *M1ThresholdEventA2APERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1ThresholdEventA2APERValueFieldReceived(v *M1ThresholdEventA2APERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM1ThresholdEventA2APERValueFieldReplay(v *M1ThresholdEventA2APERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM1ThresholdEventA2APERValueFieldWithoutReplay(v *M1ThresholdEventA2APERValue) *bool {
	return &v.withoutReplay
}
func BridgeM1ThresholdEventA2FieldExtCount(v *M1ThresholdEventA2) *int64   { return &v.extCount }
func BridgeM1ThresholdEventA2FieldExtData(v *M1ThresholdEventA2) *[][]byte { return &v.extData }
func BridgeM1ThresholdEventA2FieldExtOrigin(v *M1ThresholdEventA2) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM1ThresholdEventA2FieldExtPresent(v *M1ThresholdEventA2) *[]bool       { return &v.extPresent }
func BridgeM1ThresholdEventA2FieldExtWire(v *M1ThresholdEventA2) *[]aper.WireSpan { return &v.extWire }
func BridgeM1ThresholdEventA2FieldIEExtensionsIndef(v *M1ThresholdEventA2) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM1ThresholdEventA2FieldPerExtPadding(v *M1ThresholdEventA2) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM1ThresholdEventA2FieldPerPadding(v *M1ThresholdEventA2) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM1ThresholdEventA2FieldReceived(v *M1ThresholdEventA2) *bool { return &v.received }
func BridgeM1ThresholdEventA2FieldReceivedAbsolute(v *M1ThresholdEventA2) *bool {
	return &v.receivedAbsolute
}
func BridgeM1ThresholdEventA2FieldReceivedBytes(v *M1ThresholdEventA2) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM1ThresholdEventA2FieldReceivedLocation(v *M1ThresholdEventA2) *aper.Location {
	return &v.receivedLocation
}
func BridgeM1ThresholdEventA2FieldReplay(v *M1ThresholdEventA2) *aper.Snapshot { return &v.replay }
func BridgeM1ThresholdEventA2FieldStream(v *M1ThresholdEventA2) *aper.WireSpan { return &v.stream }
func BridgeM1ThresholdEventA2FieldWithoutReplay(v *M1ThresholdEventA2) *bool   { return &v.withoutReplay }
func BridgeM1ThresholdEventA2MethodMarshalAPERBudget(v *M1ThresholdEventA2, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERBudgetValue(v *M1ThresholdEventA2, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERChanged(v *M1ThresholdEventA2, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERChangedValue(v *M1ThresholdEventA2, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERLegacy(v *M1ThresholdEventA2) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM1ThresholdEventA2MethodMarshalAPERNewValue(v *M1ThresholdEventA2, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERPlanned(v *M1ThresholdEventA2, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERTo(v *M1ThresholdEventA2, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM1ThresholdEventA2MethodUnmarshalAPERFrom(v *M1ThresholdEventA2, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM1ThresholdEventA2MethodUnmarshalAPERLegacy(v *M1ThresholdEventA2, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM1ThresholdEventA2MethodUnmarshalAPERWithOptions(v *M1ThresholdEventA2, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM1ThresholdEventA2ValueCodecFieldCapture(v *M1ThresholdEventA2ValueCodec) *func(M1ThresholdEventA2, aper.DecodeState) (M1ThresholdEventA2, aper.Snapshot) {
	return &v.capture
}
func BridgeM1ThresholdEventA2ValueCodecFieldCompare(v *M1ThresholdEventA2ValueCodec) *func(M1ThresholdEventA2, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1ThresholdEventA2ValueCodecFieldContext(v *M1ThresholdEventA2ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1ThresholdEventA2ValueCodecFieldDecode(v *M1ThresholdEventA2ValueCodec) *func([]byte, aper.DecodeState) (M1ThresholdEventA2, error) {
	return &v.decode
}
func BridgeM1ThresholdEventA2ValueCodecFieldEncode(v *M1ThresholdEventA2ValueCodec) *func(M1ThresholdEventA2, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1ThresholdEventA2ValueCodecFieldPath(v *M1ThresholdEventA2ValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1ThresholdEventA2ValueCodecMethodEncodeBudgetValue(v M1ThresholdEventA2ValueCodec, a0 M1ThresholdEventA2, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM1ThresholdEventA2ValueCodecMethodEncodeChanged(v M1ThresholdEventA2ValueCodec, a0 M1ThresholdEventA2, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM3ConfigurationAPERValueFieldContext(v *M3ConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM3ConfigurationAPERValueFieldReceived(v *M3ConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM3ConfigurationAPERValueFieldReplay(v *M3ConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM3ConfigurationAPERValueFieldWithoutReplay(v *M3ConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeM3ConfigurationFieldExtCount(v *M3Configuration) *int64   { return &v.extCount }
func BridgeM3ConfigurationFieldExtData(v *M3Configuration) *[][]byte { return &v.extData }
func BridgeM3ConfigurationFieldExtOrigin(v *M3Configuration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM3ConfigurationFieldExtPresent(v *M3Configuration) *[]bool       { return &v.extPresent }
func BridgeM3ConfigurationFieldExtWire(v *M3Configuration) *[]aper.WireSpan { return &v.extWire }
func BridgeM3ConfigurationFieldIEExtensionsIndef(v *M3Configuration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM3ConfigurationFieldPerExtPadding(v *M3Configuration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM3ConfigurationFieldPerPadding(v *M3Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM3ConfigurationFieldReceived(v *M3Configuration) *bool         { return &v.received }
func BridgeM3ConfigurationFieldReceivedAbsolute(v *M3Configuration) *bool { return &v.receivedAbsolute }
func BridgeM3ConfigurationFieldReceivedBytes(v *M3Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM3ConfigurationFieldReceivedLocation(v *M3Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM3ConfigurationFieldReplay(v *M3Configuration) *aper.Snapshot { return &v.replay }
func BridgeM3ConfigurationFieldStream(v *M3Configuration) *aper.WireSpan { return &v.stream }
func BridgeM3ConfigurationFieldWithoutReplay(v *M3Configuration) *bool   { return &v.withoutReplay }
func BridgeM3ConfigurationMethodMarshalAPERBudget(v *M3Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM3ConfigurationMethodMarshalAPERBudgetValue(v *M3Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM3ConfigurationMethodMarshalAPERChanged(v *M3Configuration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM3ConfigurationMethodMarshalAPERChangedValue(v *M3Configuration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM3ConfigurationMethodMarshalAPERLegacy(v *M3Configuration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM3ConfigurationMethodMarshalAPERNewValue(v *M3Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM3ConfigurationMethodMarshalAPERPlanned(v *M3Configuration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM3ConfigurationMethodMarshalAPERTo(v *M3Configuration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM3ConfigurationMethodUnmarshalAPERFrom(v *M3Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM3ConfigurationMethodUnmarshalAPERLegacy(v *M3Configuration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM3ConfigurationMethodUnmarshalAPERWithOptions(v *M3Configuration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM3ConfigurationValueCodecFieldCapture(v *M3ConfigurationValueCodec) *func(M3Configuration, aper.DecodeState) (M3Configuration, aper.Snapshot) {
	return &v.capture
}
func BridgeM3ConfigurationValueCodecFieldCompare(v *M3ConfigurationValueCodec) *func(M3Configuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM3ConfigurationValueCodecFieldContext(v *M3ConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM3ConfigurationValueCodecFieldDecode(v *M3ConfigurationValueCodec) *func([]byte, aper.DecodeState) (M3Configuration, error) {
	return &v.decode
}
func BridgeM3ConfigurationValueCodecFieldEncode(v *M3ConfigurationValueCodec) *func(M3Configuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM3ConfigurationValueCodecFieldPath(v *M3ConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeM3ConfigurationValueCodecMethodEncodeBudgetValue(v M3ConfigurationValueCodec, a0 M3Configuration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM3ConfigurationValueCodecMethodEncodeChanged(v M3ConfigurationValueCodec, a0 M3Configuration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM4ConfigurationAPERValueFieldContext(v *M4ConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4ConfigurationAPERValueFieldReceived(v *M4ConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM4ConfigurationAPERValueFieldReplay(v *M4ConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM4ConfigurationAPERValueFieldWithoutReplay(v *M4ConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeM4ConfigurationFieldExtCount(v *M4Configuration) *int64   { return &v.extCount }
func BridgeM4ConfigurationFieldExtData(v *M4Configuration) *[][]byte { return &v.extData }
func BridgeM4ConfigurationFieldExtOrigin(v *M4Configuration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM4ConfigurationFieldExtPresent(v *M4Configuration) *[]bool       { return &v.extPresent }
func BridgeM4ConfigurationFieldExtWire(v *M4Configuration) *[]aper.WireSpan { return &v.extWire }
func BridgeM4ConfigurationFieldIEExtensionsIndef(v *M4Configuration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM4ConfigurationFieldPerExtPadding(v *M4Configuration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM4ConfigurationFieldPerPadding(v *M4Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM4ConfigurationFieldReceived(v *M4Configuration) *bool         { return &v.received }
func BridgeM4ConfigurationFieldReceivedAbsolute(v *M4Configuration) *bool { return &v.receivedAbsolute }
func BridgeM4ConfigurationFieldReceivedBytes(v *M4Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM4ConfigurationFieldReceivedLocation(v *M4Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM4ConfigurationFieldReplay(v *M4Configuration) *aper.Snapshot { return &v.replay }
func BridgeM4ConfigurationFieldStream(v *M4Configuration) *aper.WireSpan { return &v.stream }
func BridgeM4ConfigurationFieldWithoutReplay(v *M4Configuration) *bool   { return &v.withoutReplay }
func BridgeM4ConfigurationMethodMarshalAPERBudget(v *M4Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM4ConfigurationMethodMarshalAPERBudgetValue(v *M4Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM4ConfigurationMethodMarshalAPERChanged(v *M4Configuration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM4ConfigurationMethodMarshalAPERChangedValue(v *M4Configuration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM4ConfigurationMethodMarshalAPERLegacy(v *M4Configuration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM4ConfigurationMethodMarshalAPERNewValue(v *M4Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM4ConfigurationMethodMarshalAPERPlanned(v *M4Configuration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM4ConfigurationMethodMarshalAPERTo(v *M4Configuration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM4ConfigurationMethodUnmarshalAPERFrom(v *M4Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM4ConfigurationMethodUnmarshalAPERLegacy(v *M4Configuration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM4ConfigurationMethodUnmarshalAPERWithOptions(v *M4Configuration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM4ConfigurationValueCodecFieldCapture(v *M4ConfigurationValueCodec) *func(M4Configuration, aper.DecodeState) (M4Configuration, aper.Snapshot) {
	return &v.capture
}
func BridgeM4ConfigurationValueCodecFieldCompare(v *M4ConfigurationValueCodec) *func(M4Configuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM4ConfigurationValueCodecFieldContext(v *M4ConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4ConfigurationValueCodecFieldDecode(v *M4ConfigurationValueCodec) *func([]byte, aper.DecodeState) (M4Configuration, error) {
	return &v.decode
}
func BridgeM4ConfigurationValueCodecFieldEncode(v *M4ConfigurationValueCodec) *func(M4Configuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM4ConfigurationValueCodecFieldPath(v *M4ConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeM4ConfigurationValueCodecMethodEncodeBudgetValue(v M4ConfigurationValueCodec, a0 M4Configuration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM4ConfigurationValueCodecMethodEncodeChanged(v M4ConfigurationValueCodec, a0 M4Configuration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM5ConfigurationAPERValueFieldContext(v *M5ConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5ConfigurationAPERValueFieldReceived(v *M5ConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM5ConfigurationAPERValueFieldReplay(v *M5ConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM5ConfigurationAPERValueFieldWithoutReplay(v *M5ConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeM5ConfigurationFieldExtCount(v *M5Configuration) *int64   { return &v.extCount }
func BridgeM5ConfigurationFieldExtData(v *M5Configuration) *[][]byte { return &v.extData }
func BridgeM5ConfigurationFieldExtOrigin(v *M5Configuration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM5ConfigurationFieldExtPresent(v *M5Configuration) *[]bool       { return &v.extPresent }
func BridgeM5ConfigurationFieldExtWire(v *M5Configuration) *[]aper.WireSpan { return &v.extWire }
func BridgeM5ConfigurationFieldIEExtensionsIndef(v *M5Configuration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM5ConfigurationFieldPerExtPadding(v *M5Configuration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM5ConfigurationFieldPerPadding(v *M5Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM5ConfigurationFieldReceived(v *M5Configuration) *bool         { return &v.received }
func BridgeM5ConfigurationFieldReceivedAbsolute(v *M5Configuration) *bool { return &v.receivedAbsolute }
func BridgeM5ConfigurationFieldReceivedBytes(v *M5Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM5ConfigurationFieldReceivedLocation(v *M5Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM5ConfigurationFieldReplay(v *M5Configuration) *aper.Snapshot { return &v.replay }
func BridgeM5ConfigurationFieldStream(v *M5Configuration) *aper.WireSpan { return &v.stream }
func BridgeM5ConfigurationFieldWithoutReplay(v *M5Configuration) *bool   { return &v.withoutReplay }
func BridgeM5ConfigurationMethodMarshalAPERBudget(v *M5Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM5ConfigurationMethodMarshalAPERBudgetValue(v *M5Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM5ConfigurationMethodMarshalAPERChanged(v *M5Configuration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM5ConfigurationMethodMarshalAPERChangedValue(v *M5Configuration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM5ConfigurationMethodMarshalAPERLegacy(v *M5Configuration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM5ConfigurationMethodMarshalAPERNewValue(v *M5Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM5ConfigurationMethodMarshalAPERPlanned(v *M5Configuration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM5ConfigurationMethodMarshalAPERTo(v *M5Configuration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM5ConfigurationMethodUnmarshalAPERFrom(v *M5Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM5ConfigurationMethodUnmarshalAPERLegacy(v *M5Configuration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM5ConfigurationMethodUnmarshalAPERWithOptions(v *M5Configuration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM5ConfigurationValueCodecFieldCapture(v *M5ConfigurationValueCodec) *func(M5Configuration, aper.DecodeState) (M5Configuration, aper.Snapshot) {
	return &v.capture
}
func BridgeM5ConfigurationValueCodecFieldCompare(v *M5ConfigurationValueCodec) *func(M5Configuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM5ConfigurationValueCodecFieldContext(v *M5ConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5ConfigurationValueCodecFieldDecode(v *M5ConfigurationValueCodec) *func([]byte, aper.DecodeState) (M5Configuration, error) {
	return &v.decode
}
func BridgeM5ConfigurationValueCodecFieldEncode(v *M5ConfigurationValueCodec) *func(M5Configuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM5ConfigurationValueCodecFieldPath(v *M5ConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeM5ConfigurationValueCodecMethodEncodeBudgetValue(v M5ConfigurationValueCodec, a0 M5Configuration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM5ConfigurationValueCodecMethodEncodeChanged(v M5ConfigurationValueCodec, a0 M5Configuration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM6ConfigurationAPERValueFieldContext(v *M6ConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6ConfigurationAPERValueFieldReceived(v *M6ConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM6ConfigurationAPERValueFieldReplay(v *M6ConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM6ConfigurationAPERValueFieldWithoutReplay(v *M6ConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeM6ConfigurationFieldExtCount(v *M6Configuration) *int64   { return &v.extCount }
func BridgeM6ConfigurationFieldExtData(v *M6Configuration) *[][]byte { return &v.extData }
func BridgeM6ConfigurationFieldExtOrigin(v *M6Configuration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM6ConfigurationFieldExtPresent(v *M6Configuration) *[]bool       { return &v.extPresent }
func BridgeM6ConfigurationFieldExtWire(v *M6Configuration) *[]aper.WireSpan { return &v.extWire }
func BridgeM6ConfigurationFieldIEExtensionsIndef(v *M6Configuration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM6ConfigurationFieldPerExtPadding(v *M6Configuration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM6ConfigurationFieldPerPadding(v *M6Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM6ConfigurationFieldReceived(v *M6Configuration) *bool         { return &v.received }
func BridgeM6ConfigurationFieldReceivedAbsolute(v *M6Configuration) *bool { return &v.receivedAbsolute }
func BridgeM6ConfigurationFieldReceivedBytes(v *M6Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM6ConfigurationFieldReceivedLocation(v *M6Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM6ConfigurationFieldReplay(v *M6Configuration) *aper.Snapshot { return &v.replay }
func BridgeM6ConfigurationFieldStream(v *M6Configuration) *aper.WireSpan { return &v.stream }
func BridgeM6ConfigurationFieldWithoutReplay(v *M6Configuration) *bool   { return &v.withoutReplay }
func BridgeM6ConfigurationMethodMarshalAPERBudget(v *M6Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM6ConfigurationMethodMarshalAPERBudgetValue(v *M6Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM6ConfigurationMethodMarshalAPERChanged(v *M6Configuration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM6ConfigurationMethodMarshalAPERChangedValue(v *M6Configuration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM6ConfigurationMethodMarshalAPERLegacy(v *M6Configuration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM6ConfigurationMethodMarshalAPERNewValue(v *M6Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM6ConfigurationMethodMarshalAPERPlanned(v *M6Configuration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM6ConfigurationMethodMarshalAPERTo(v *M6Configuration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM6ConfigurationMethodUnmarshalAPERFrom(v *M6Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM6ConfigurationMethodUnmarshalAPERLegacy(v *M6Configuration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM6ConfigurationMethodUnmarshalAPERWithOptions(v *M6Configuration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM6ConfigurationValueCodecFieldCapture(v *M6ConfigurationValueCodec) *func(M6Configuration, aper.DecodeState) (M6Configuration, aper.Snapshot) {
	return &v.capture
}
func BridgeM6ConfigurationValueCodecFieldCompare(v *M6ConfigurationValueCodec) *func(M6Configuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6ConfigurationValueCodecFieldContext(v *M6ConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6ConfigurationValueCodecFieldDecode(v *M6ConfigurationValueCodec) *func([]byte, aper.DecodeState) (M6Configuration, error) {
	return &v.decode
}
func BridgeM6ConfigurationValueCodecFieldEncode(v *M6ConfigurationValueCodec) *func(M6Configuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6ConfigurationValueCodecFieldPath(v *M6ConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeM6ConfigurationValueCodecMethodEncodeBudgetValue(v M6ConfigurationValueCodec, a0 M6Configuration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM6ConfigurationValueCodecMethodEncodeChanged(v M6ConfigurationValueCodec, a0 M6Configuration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeM7ConfigurationAPERValueFieldContext(v *M7ConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7ConfigurationAPERValueFieldReceived(v *M7ConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeM7ConfigurationAPERValueFieldReplay(v *M7ConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeM7ConfigurationAPERValueFieldWithoutReplay(v *M7ConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeM7ConfigurationFieldExtCount(v *M7Configuration) *int64   { return &v.extCount }
func BridgeM7ConfigurationFieldExtData(v *M7Configuration) *[][]byte { return &v.extData }
func BridgeM7ConfigurationFieldExtOrigin(v *M7Configuration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeM7ConfigurationFieldExtPresent(v *M7Configuration) *[]bool       { return &v.extPresent }
func BridgeM7ConfigurationFieldExtWire(v *M7Configuration) *[]aper.WireSpan { return &v.extWire }
func BridgeM7ConfigurationFieldIEExtensionsIndef(v *M7Configuration) *bool {
	return &v.iEExtensionsIndef
}
func BridgeM7ConfigurationFieldPerExtPadding(v *M7Configuration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeM7ConfigurationFieldPerPadding(v *M7Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM7ConfigurationFieldReceived(v *M7Configuration) *bool         { return &v.received }
func BridgeM7ConfigurationFieldReceivedAbsolute(v *M7Configuration) *bool { return &v.receivedAbsolute }
func BridgeM7ConfigurationFieldReceivedBytes(v *M7Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM7ConfigurationFieldReceivedLocation(v *M7Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM7ConfigurationFieldReplay(v *M7Configuration) *aper.Snapshot { return &v.replay }
func BridgeM7ConfigurationFieldStream(v *M7Configuration) *aper.WireSpan { return &v.stream }
func BridgeM7ConfigurationFieldWithoutReplay(v *M7Configuration) *bool   { return &v.withoutReplay }
func BridgeM7ConfigurationMethodMarshalAPERBudget(v *M7Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM7ConfigurationMethodMarshalAPERBudgetValue(v *M7Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeM7ConfigurationMethodMarshalAPERChanged(v *M7Configuration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeM7ConfigurationMethodMarshalAPERChangedValue(v *M7Configuration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeM7ConfigurationMethodMarshalAPERLegacy(v *M7Configuration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeM7ConfigurationMethodMarshalAPERNewValue(v *M7Configuration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeM7ConfigurationMethodMarshalAPERPlanned(v *M7Configuration, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeM7ConfigurationMethodMarshalAPERTo(v *M7Configuration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM7ConfigurationMethodUnmarshalAPERFrom(v *M7Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM7ConfigurationMethodUnmarshalAPERLegacy(v *M7Configuration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeM7ConfigurationMethodUnmarshalAPERWithOptions(v *M7Configuration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeM7ConfigurationValueCodecFieldCapture(v *M7ConfigurationValueCodec) *func(M7Configuration, aper.DecodeState) (M7Configuration, aper.Snapshot) {
	return &v.capture
}
func BridgeM7ConfigurationValueCodecFieldCompare(v *M7ConfigurationValueCodec) *func(M7Configuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM7ConfigurationValueCodecFieldContext(v *M7ConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7ConfigurationValueCodecFieldDecode(v *M7ConfigurationValueCodec) *func([]byte, aper.DecodeState) (M7Configuration, error) {
	return &v.decode
}
func BridgeM7ConfigurationValueCodecFieldEncode(v *M7ConfigurationValueCodec) *func(M7Configuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM7ConfigurationValueCodecFieldPath(v *M7ConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeM7ConfigurationValueCodecMethodEncodeBudgetValue(v M7ConfigurationValueCodec, a0 M7Configuration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeM7ConfigurationValueCodecMethodEncodeChanged(v M7ConfigurationValueCodec, a0 M7Configuration, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMBSFNResultToLogAPERValueFieldContext(v *MBSFNResultToLogAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogAPERValueFieldReceived(v *MBSFNResultToLogAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMBSFNResultToLogAPERValueFieldReplay(v *MBSFNResultToLogAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNResultToLogAPERValueFieldWithoutReplay(v *MBSFNResultToLogAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNResultToLogInfoAPERValueFieldContext(v *MBSFNResultToLogInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogInfoAPERValueFieldReceived(v *MBSFNResultToLogInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMBSFNResultToLogInfoAPERValueFieldReplay(v *MBSFNResultToLogInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNResultToLogInfoAPERValueFieldWithoutReplay(v *MBSFNResultToLogInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNResultToLogInfoFieldExtCount(v *MBSFNResultToLogInfo) *int64   { return &v.extCount }
func BridgeMBSFNResultToLogInfoFieldExtData(v *MBSFNResultToLogInfo) *[][]byte { return &v.extData }
func BridgeMBSFNResultToLogInfoFieldExtOrigin(v *MBSFNResultToLogInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMBSFNResultToLogInfoFieldExtPresent(v *MBSFNResultToLogInfo) *[]bool { return &v.extPresent }
func BridgeMBSFNResultToLogInfoFieldExtWire(v *MBSFNResultToLogInfo) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMBSFNResultToLogInfoFieldIEExtensionsIndef(v *MBSFNResultToLogInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeMBSFNResultToLogInfoFieldPerExtPadding(v *MBSFNResultToLogInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMBSFNResultToLogInfoFieldPerPadding(v *MBSFNResultToLogInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMBSFNResultToLogInfoFieldReceived(v *MBSFNResultToLogInfo) *bool { return &v.received }
func BridgeMBSFNResultToLogInfoFieldReceivedAbsolute(v *MBSFNResultToLogInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeMBSFNResultToLogInfoFieldReceivedBytes(v *MBSFNResultToLogInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNResultToLogInfoFieldReceivedLocation(v *MBSFNResultToLogInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeMBSFNResultToLogInfoFieldReplay(v *MBSFNResultToLogInfo) *aper.Snapshot { return &v.replay }
func BridgeMBSFNResultToLogInfoFieldStream(v *MBSFNResultToLogInfo) *aper.WireSpan { return &v.stream }
func BridgeMBSFNResultToLogInfoFieldWithoutReplay(v *MBSFNResultToLogInfo) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERBudget(v *MBSFNResultToLogInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERBudgetValue(v *MBSFNResultToLogInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERChanged(v *MBSFNResultToLogInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERChangedValue(v *MBSFNResultToLogInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERLegacy(v *MBSFNResultToLogInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERNewValue(v *MBSFNResultToLogInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERPlanned(v *MBSFNResultToLogInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(v *MBSFNResultToLogInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMBSFNResultToLogInfoMethodUnmarshalAPERFrom(v *MBSFNResultToLogInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMBSFNResultToLogInfoMethodUnmarshalAPERLegacy(v *MBSFNResultToLogInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNResultToLogInfoMethodUnmarshalAPERWithOptions(v *MBSFNResultToLogInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMBSFNResultToLogInfoValueCodecFieldCapture(v *MBSFNResultToLogInfoValueCodec) *func(MBSFNResultToLogInfo, aper.DecodeState) (MBSFNResultToLogInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNResultToLogInfoValueCodecFieldCompare(v *MBSFNResultToLogInfoValueCodec) *func(MBSFNResultToLogInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMBSFNResultToLogInfoValueCodecFieldContext(v *MBSFNResultToLogInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogInfoValueCodecFieldDecode(v *MBSFNResultToLogInfoValueCodec) *func([]byte, aper.DecodeState) (MBSFNResultToLogInfo, error) {
	return &v.decode
}
func BridgeMBSFNResultToLogInfoValueCodecFieldEncode(v *MBSFNResultToLogInfoValueCodec) *func(MBSFNResultToLogInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNResultToLogInfoValueCodecFieldPath(v *MBSFNResultToLogInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNResultToLogInfoValueCodecMethodEncodeBudgetValue(v MBSFNResultToLogInfoValueCodec, a0 MBSFNResultToLogInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMBSFNResultToLogInfoValueCodecMethodEncodeChanged(v MBSFNResultToLogInfoValueCodec, a0 MBSFNResultToLogInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMBSFNResultToLogValueCodecFieldCapture(v *MBSFNResultToLogValueCodec) *func(MBSFNResultToLog, aper.DecodeState) (MBSFNResultToLog, aper.Snapshot) {
	return &v.capture
}
func BridgeMBSFNResultToLogValueCodecFieldCompare(v *MBSFNResultToLogValueCodec) *func(MBSFNResultToLog, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMBSFNResultToLogValueCodecFieldContext(v *MBSFNResultToLogValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMBSFNResultToLogValueCodecFieldDecode(v *MBSFNResultToLogValueCodec) *func([]byte, aper.DecodeState) (MBSFNResultToLog, error) {
	return &v.decode
}
func BridgeMBSFNResultToLogValueCodecFieldEncode(v *MBSFNResultToLogValueCodec) *func(MBSFNResultToLog, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMBSFNResultToLogValueCodecFieldPath(v *MBSFNResultToLogValueCodec) *aper.Path {
	return &v.path
}
func BridgeMBSFNResultToLogValueCodecMethodEncodeBudgetValue(v MBSFNResultToLogValueCodec, a0 MBSFNResultToLog, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMBSFNResultToLogValueCodecMethodEncodeChanged(v MBSFNResultToLogValueCodec, a0 MBSFNResultToLog, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMDTModeExtensionAPERValueFieldContext(v *MDTModeExtensionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionAPERValueFieldReceived(v *MDTModeExtensionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMDTModeExtensionAPERValueFieldReplay(v *MDTModeExtensionAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionAPERValueFieldWithoutReplay(v *MDTModeExtensionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionFieldPerPadding(v *MDTModeExtension) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMDTModeExtensionFieldReceived(v *MDTModeExtension) *bool { return &v.received }
func BridgeMDTModeExtensionFieldReceivedAbsolute(v *MDTModeExtension) *bool {
	return &v.receivedAbsolute
}
func BridgeMDTModeExtensionFieldReceivedBytes(v *MDTModeExtension) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMDTModeExtensionFieldReceivedLocation(v *MDTModeExtension) *aper.Location {
	return &v.receivedLocation
}
func BridgeMDTModeExtensionFieldReplay(v *MDTModeExtension) *aper.Snapshot { return &v.replay }
func BridgeMDTModeExtensionFieldStream(v *MDTModeExtension) *aper.WireSpan { return &v.stream }
func BridgeMDTModeExtensionFieldWithoutReplay(v *MDTModeExtension) *bool   { return &v.withoutReplay }
func BridgeMDTModeExtensionMethodMarshalAPERBudget(v *MDTModeExtension, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMDTModeExtensionMethodMarshalAPERBudgetValue(v *MDTModeExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMDTModeExtensionMethodMarshalAPERChanged(v *MDTModeExtension, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMDTModeExtensionMethodMarshalAPERChangedValue(v *MDTModeExtension, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMDTModeExtensionMethodMarshalAPERLegacy(v *MDTModeExtension) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMDTModeExtensionMethodMarshalAPERNewValue(v *MDTModeExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMDTModeExtensionMethodMarshalAPERPlanned(v *MDTModeExtension, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMDTModeExtensionMethodMarshalAPERTo(v *MDTModeExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTModeExtensionMethodUnmarshalAPERFrom(v *MDTModeExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTModeExtensionMethodUnmarshalAPERLegacy(v *MDTModeExtension, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMDTModeExtensionMethodUnmarshalAPERWithOptions(v *MDTModeExtension, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMDTModeExtensionValueCodecFieldCapture(v *MDTModeExtensionValueCodec) *func(MDTModeExtension, aper.DecodeState) (MDTModeExtension, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionValueCodecFieldCompare(v *MDTModeExtensionValueCodec) *func(MDTModeExtension, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionValueCodecFieldContext(v *MDTModeExtensionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionValueCodecFieldDecode(v *MDTModeExtensionValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtension, error) {
	return &v.decode
}
func BridgeMDTModeExtensionValueCodecFieldEncode(v *MDTModeExtensionValueCodec) *func(MDTModeExtension, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionValueCodecFieldPath(v *MDTModeExtensionValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionValueCodecMethodEncodeBudgetValue(v MDTModeExtensionValueCodec, a0 MDTModeExtension, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMDTModeExtensionValueCodecMethodEncodeChanged(v MDTModeExtensionValueCodec, a0 MDTModeExtension, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMECPRelocationIndicationAPERValueFieldContext(v *MMECPRelocationIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationAPERValueFieldReceived(v *MMECPRelocationIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMECPRelocationIndicationAPERValueFieldReplay(v *MMECPRelocationIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMECPRelocationIndicationAPERValueFieldWithoutReplay(v *MMECPRelocationIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMECPRelocationIndicationFieldExtCount(v *MMECPRelocationIndication) *int64 {
	return &v.extCount
}
func BridgeMMECPRelocationIndicationFieldExtData(v *MMECPRelocationIndication) *[][]byte {
	return &v.extData
}
func BridgeMMECPRelocationIndicationFieldExtOrigin(v *MMECPRelocationIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMECPRelocationIndicationFieldExtPresent(v *MMECPRelocationIndication) *[]bool {
	return &v.extPresent
}
func BridgeMMECPRelocationIndicationFieldExtWire(v *MMECPRelocationIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMECPRelocationIndicationFieldPerExtPadding(v *MMECPRelocationIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMECPRelocationIndicationFieldPerPadding(v *MMECPRelocationIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMECPRelocationIndicationFieldProtocolIEsIndef(v *MMECPRelocationIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMECPRelocationIndicationFieldReceived(v *MMECPRelocationIndication) *bool {
	return &v.received
}
func BridgeMMECPRelocationIndicationFieldReceivedAbsolute(v *MMECPRelocationIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeMMECPRelocationIndicationFieldReceivedBytes(v *MMECPRelocationIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMECPRelocationIndicationFieldReceivedLocation(v *MMECPRelocationIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMECPRelocationIndicationFieldReplay(v *MMECPRelocationIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeMMECPRelocationIndicationFieldStream(v *MMECPRelocationIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeMMECPRelocationIndicationFieldWithoutReplay(v *MMECPRelocationIndication) *bool {
	return &v.withoutReplay
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v *MMECPRelocationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERBudgetValue(v *MMECPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERChanged(v *MMECPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERChangedValue(v *MMECPRelocationIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERLegacy(v *MMECPRelocationIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERNewValue(v *MMECPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERPlanned(v *MMECPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMECPRelocationIndicationMethodMarshalAPERTo(v *MMECPRelocationIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMECPRelocationIndicationMethodUnmarshalAPERFrom(v *MMECPRelocationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMECPRelocationIndicationMethodUnmarshalAPERLegacy(v *MMECPRelocationIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMECPRelocationIndicationMethodUnmarshalAPERWithOptions(v *MMECPRelocationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMECPRelocationIndicationValueCodecFieldCapture(v *MMECPRelocationIndicationValueCodec) *func(MMECPRelocationIndication, aper.DecodeState) (MMECPRelocationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECPRelocationIndicationValueCodecFieldCompare(v *MMECPRelocationIndicationValueCodec) *func(MMECPRelocationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECPRelocationIndicationValueCodecFieldContext(v *MMECPRelocationIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECPRelocationIndicationValueCodecFieldDecode(v *MMECPRelocationIndicationValueCodec) *func([]byte, aper.DecodeState) (MMECPRelocationIndication, error) {
	return &v.decode
}
func BridgeMMECPRelocationIndicationValueCodecFieldEncode(v *MMECPRelocationIndicationValueCodec) *func(MMECPRelocationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECPRelocationIndicationValueCodecFieldPath(v *MMECPRelocationIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMECPRelocationIndicationValueCodecMethodEncodeBudgetValue(v MMECPRelocationIndicationValueCodec, a0 MMECPRelocationIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMECPRelocationIndicationValueCodecMethodEncodeChanged(v MMECPRelocationIndicationValueCodec, a0 MMECPRelocationIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementThresholdA2APERValueFieldContext(v *MeasurementThresholdA2APERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdA2APERValueFieldReceived(v *MeasurementThresholdA2APERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementThresholdA2APERValueFieldReplay(v *MeasurementThresholdA2APERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementThresholdA2APERValueFieldWithoutReplay(v *MeasurementThresholdA2APERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementThresholdA2FieldPerOpenTypePadding(v *MeasurementThresholdA2) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMeasurementThresholdA2FieldPerPadding(v *MeasurementThresholdA2) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMeasurementThresholdA2FieldReceived(v *MeasurementThresholdA2) *bool { return &v.received }
func BridgeMeasurementThresholdA2FieldReceivedAbsolute(v *MeasurementThresholdA2) *bool {
	return &v.receivedAbsolute
}
func BridgeMeasurementThresholdA2FieldReceivedBytes(v *MeasurementThresholdA2) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementThresholdA2FieldReceivedLocation(v *MeasurementThresholdA2) *aper.Location {
	return &v.receivedLocation
}
func BridgeMeasurementThresholdA2FieldReplay(v *MeasurementThresholdA2) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementThresholdA2FieldStream(v *MeasurementThresholdA2) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementThresholdA2FieldWithoutReplay(v *MeasurementThresholdA2) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementThresholdA2MethodMarshalAPERBudget(v *MeasurementThresholdA2, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERBudgetValue(v *MeasurementThresholdA2, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERChanged(v *MeasurementThresholdA2, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERChangedValue(v *MeasurementThresholdA2, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERLegacy(v *MeasurementThresholdA2) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementThresholdA2MethodMarshalAPERNewValue(v *MeasurementThresholdA2, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERPlanned(v *MeasurementThresholdA2, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMeasurementThresholdA2MethodMarshalAPERTo(v *MeasurementThresholdA2, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementThresholdA2MethodUnmarshalAPERFrom(v *MeasurementThresholdA2, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementThresholdA2MethodUnmarshalAPERLegacy(v *MeasurementThresholdA2, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementThresholdA2MethodUnmarshalAPERWithOptions(v *MeasurementThresholdA2, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementThresholdA2ValueCodecFieldCapture(v *MeasurementThresholdA2ValueCodec) *func(MeasurementThresholdA2, aper.DecodeState) (MeasurementThresholdA2, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdA2ValueCodecFieldCompare(v *MeasurementThresholdA2ValueCodec) *func(MeasurementThresholdA2, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdA2ValueCodecFieldContext(v *MeasurementThresholdA2ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdA2ValueCodecFieldDecode(v *MeasurementThresholdA2ValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdA2, error) {
	return &v.decode
}
func BridgeMeasurementThresholdA2ValueCodecFieldEncode(v *MeasurementThresholdA2ValueCodec) *func(MeasurementThresholdA2, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdA2ValueCodecFieldPath(v *MeasurementThresholdA2ValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdA2ValueCodecMethodEncodeBudgetValue(v MeasurementThresholdA2ValueCodec, a0 MeasurementThresholdA2, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMeasurementThresholdA2ValueCodecMethodEncodeChanged(v MeasurementThresholdA2ValueCodec, a0 MeasurementThresholdA2, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementThresholdL1LoggedMDTAPERValueFieldContext(v *MeasurementThresholdL1LoggedMDTAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTAPERValueFieldReceived(v *MeasurementThresholdL1LoggedMDTAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementThresholdL1LoggedMDTAPERValueFieldReplay(v *MeasurementThresholdL1LoggedMDTAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementThresholdL1LoggedMDTAPERValueFieldWithoutReplay(v *MeasurementThresholdL1LoggedMDTAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementThresholdL1LoggedMDTFieldPerOpenTypePadding(v *MeasurementThresholdL1LoggedMDT) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMeasurementThresholdL1LoggedMDTFieldPerPadding(v *MeasurementThresholdL1LoggedMDT) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMeasurementThresholdL1LoggedMDTFieldReceived(v *MeasurementThresholdL1LoggedMDT) *bool {
	return &v.received
}
func BridgeMeasurementThresholdL1LoggedMDTFieldReceivedAbsolute(v *MeasurementThresholdL1LoggedMDT) *bool {
	return &v.receivedAbsolute
}
func BridgeMeasurementThresholdL1LoggedMDTFieldReceivedBytes(v *MeasurementThresholdL1LoggedMDT) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementThresholdL1LoggedMDTFieldReceivedLocation(v *MeasurementThresholdL1LoggedMDT) *aper.Location {
	return &v.receivedLocation
}
func BridgeMeasurementThresholdL1LoggedMDTFieldReplay(v *MeasurementThresholdL1LoggedMDT) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementThresholdL1LoggedMDTFieldStream(v *MeasurementThresholdL1LoggedMDT) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementThresholdL1LoggedMDTFieldWithoutReplay(v *MeasurementThresholdL1LoggedMDT) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget(v *MeasurementThresholdL1LoggedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudgetValue(v *MeasurementThresholdL1LoggedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERChanged(v *MeasurementThresholdL1LoggedMDT, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERChangedValue(v *MeasurementThresholdL1LoggedMDT, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERLegacy(v *MeasurementThresholdL1LoggedMDT) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERNewValue(v *MeasurementThresholdL1LoggedMDT, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERPlanned(v *MeasurementThresholdL1LoggedMDT, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERTo(v *MeasurementThresholdL1LoggedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodUnmarshalAPERFrom(v *MeasurementThresholdL1LoggedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodUnmarshalAPERLegacy(v *MeasurementThresholdL1LoggedMDT, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodUnmarshalAPERWithOptions(v *MeasurementThresholdL1LoggedMDT, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldCapture(v *MeasurementThresholdL1LoggedMDTValueCodec) *func(MeasurementThresholdL1LoggedMDT, aper.DecodeState) (MeasurementThresholdL1LoggedMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldCompare(v *MeasurementThresholdL1LoggedMDTValueCodec) *func(MeasurementThresholdL1LoggedMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldContext(v *MeasurementThresholdL1LoggedMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldDecode(v *MeasurementThresholdL1LoggedMDTValueCodec) *func([]byte, aper.DecodeState) (MeasurementThresholdL1LoggedMDT, error) {
	return &v.decode
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldEncode(v *MeasurementThresholdL1LoggedMDTValueCodec) *func(MeasurementThresholdL1LoggedMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecFieldPath(v *MeasurementThresholdL1LoggedMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecMethodEncodeBudgetValue(v MeasurementThresholdL1LoggedMDTValueCodec, a0 MeasurementThresholdL1LoggedMDT, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMeasurementThresholdL1LoggedMDTValueCodecMethodEncodeChanged(v MeasurementThresholdL1LoggedMDTValueCodec, a0 MeasurementThresholdL1LoggedMDT, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMultiCellLoadReportingResponseAPERValueFieldContext(v *MultiCellLoadReportingResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingResponseAPERValueFieldReceived(v *MultiCellLoadReportingResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMultiCellLoadReportingResponseAPERValueFieldReplay(v *MultiCellLoadReportingResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingResponseAPERValueFieldWithoutReplay(v *MultiCellLoadReportingResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingResponseItemAPERValueFieldContext(v *MultiCellLoadReportingResponseItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingResponseItemAPERValueFieldReceived(v *MultiCellLoadReportingResponseItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMultiCellLoadReportingResponseItemAPERValueFieldReplay(v *MultiCellLoadReportingResponseItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingResponseItemAPERValueFieldWithoutReplay(v *MultiCellLoadReportingResponseItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingResponseItemFieldPerOpenTypePadding(v *MultiCellLoadReportingResponseItem) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMultiCellLoadReportingResponseItemFieldPerPadding(v *MultiCellLoadReportingResponseItem) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMultiCellLoadReportingResponseItemFieldReceived(v *MultiCellLoadReportingResponseItem) *bool {
	return &v.received
}
func BridgeMultiCellLoadReportingResponseItemFieldReceivedAbsolute(v *MultiCellLoadReportingResponseItem) *bool {
	return &v.receivedAbsolute
}
func BridgeMultiCellLoadReportingResponseItemFieldReceivedBytes(v *MultiCellLoadReportingResponseItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMultiCellLoadReportingResponseItemFieldReceivedLocation(v *MultiCellLoadReportingResponseItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeMultiCellLoadReportingResponseItemFieldReplay(v *MultiCellLoadReportingResponseItem) *aper.Snapshot {
	return &v.replay
}
func BridgeMultiCellLoadReportingResponseItemFieldStream(v *MultiCellLoadReportingResponseItem) *aper.WireSpan {
	return &v.stream
}
func BridgeMultiCellLoadReportingResponseItemFieldWithoutReplay(v *MultiCellLoadReportingResponseItem) *bool {
	return &v.withoutReplay
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget(v *MultiCellLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudgetValue(v *MultiCellLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERChanged(v *MultiCellLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERChangedValue(v *MultiCellLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERLegacy(v *MultiCellLoadReportingResponseItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERNewValue(v *MultiCellLoadReportingResponseItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERPlanned(v *MultiCellLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(v *MultiCellLoadReportingResponseItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERFrom(v *MultiCellLoadReportingResponseItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERLegacy(v *MultiCellLoadReportingResponseItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERWithOptions(v *MultiCellLoadReportingResponseItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldCapture(v *MultiCellLoadReportingResponseItemValueCodec) *func(MultiCellLoadReportingResponseItem, aper.DecodeState) (MultiCellLoadReportingResponseItem, aper.Snapshot) {
	return &v.capture
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldCompare(v *MultiCellLoadReportingResponseItemValueCodec) *func(MultiCellLoadReportingResponseItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldContext(v *MultiCellLoadReportingResponseItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldDecode(v *MultiCellLoadReportingResponseItemValueCodec) *func([]byte, aper.DecodeState) (MultiCellLoadReportingResponseItem, error) {
	return &v.decode
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldEncode(v *MultiCellLoadReportingResponseItemValueCodec) *func(MultiCellLoadReportingResponseItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMultiCellLoadReportingResponseItemValueCodecFieldPath(v *MultiCellLoadReportingResponseItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeMultiCellLoadReportingResponseItemValueCodecMethodEncodeBudgetValue(v MultiCellLoadReportingResponseItemValueCodec, a0 MultiCellLoadReportingResponseItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseItemValueCodecMethodEncodeChanged(v MultiCellLoadReportingResponseItemValueCodec, a0 MultiCellLoadReportingResponseItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldCapture(v *MultiCellLoadReportingResponseValueCodec) *func(MultiCellLoadReportingResponse, aper.DecodeState) (MultiCellLoadReportingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldCompare(v *MultiCellLoadReportingResponseValueCodec) *func(MultiCellLoadReportingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldContext(v *MultiCellLoadReportingResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldDecode(v *MultiCellLoadReportingResponseValueCodec) *func([]byte, aper.DecodeState) (MultiCellLoadReportingResponse, error) {
	return &v.decode
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldEncode(v *MultiCellLoadReportingResponseValueCodec) *func(MultiCellLoadReportingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMultiCellLoadReportingResponseValueCodecFieldPath(v *MultiCellLoadReportingResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeMultiCellLoadReportingResponseValueCodecMethodEncodeBudgetValue(v MultiCellLoadReportingResponseValueCodec, a0 MultiCellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMultiCellLoadReportingResponseValueCodecMethodEncodeChanged(v MultiCellLoadReportingResponseValueCodec, a0 MultiCellLoadReportingResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMutingPatternInformationAPERValueFieldContext(v *MutingPatternInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMutingPatternInformationAPERValueFieldReceived(v *MutingPatternInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMutingPatternInformationAPERValueFieldReplay(v *MutingPatternInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMutingPatternInformationAPERValueFieldWithoutReplay(v *MutingPatternInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMutingPatternInformationFieldExtCount(v *MutingPatternInformation) *int64 {
	return &v.extCount
}
func BridgeMutingPatternInformationFieldExtData(v *MutingPatternInformation) *[][]byte {
	return &v.extData
}
func BridgeMutingPatternInformationFieldExtOrigin(v *MutingPatternInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMutingPatternInformationFieldExtPresent(v *MutingPatternInformation) *[]bool {
	return &v.extPresent
}
func BridgeMutingPatternInformationFieldExtWire(v *MutingPatternInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMutingPatternInformationFieldIEExtensionsIndef(v *MutingPatternInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeMutingPatternInformationFieldPerExtPadding(v *MutingPatternInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMutingPatternInformationFieldPerPadding(v *MutingPatternInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMutingPatternInformationFieldReceived(v *MutingPatternInformation) *bool {
	return &v.received
}
func BridgeMutingPatternInformationFieldReceivedAbsolute(v *MutingPatternInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeMutingPatternInformationFieldReceivedBytes(v *MutingPatternInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMutingPatternInformationFieldReceivedLocation(v *MutingPatternInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeMutingPatternInformationFieldReplay(v *MutingPatternInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeMutingPatternInformationFieldStream(v *MutingPatternInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeMutingPatternInformationFieldWithoutReplay(v *MutingPatternInformation) *bool {
	return &v.withoutReplay
}
func BridgeMutingPatternInformationMethodMarshalAPERBudget(v *MutingPatternInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMutingPatternInformationMethodMarshalAPERBudgetValue(v *MutingPatternInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMutingPatternInformationMethodMarshalAPERChanged(v *MutingPatternInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMutingPatternInformationMethodMarshalAPERChangedValue(v *MutingPatternInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMutingPatternInformationMethodMarshalAPERLegacy(v *MutingPatternInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMutingPatternInformationMethodMarshalAPERNewValue(v *MutingPatternInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMutingPatternInformationMethodMarshalAPERPlanned(v *MutingPatternInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMutingPatternInformationMethodMarshalAPERTo(v *MutingPatternInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMutingPatternInformationMethodUnmarshalAPERFrom(v *MutingPatternInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMutingPatternInformationMethodUnmarshalAPERLegacy(v *MutingPatternInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMutingPatternInformationMethodUnmarshalAPERWithOptions(v *MutingPatternInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMutingPatternInformationValueCodecFieldCapture(v *MutingPatternInformationValueCodec) *func(MutingPatternInformation, aper.DecodeState) (MutingPatternInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeMutingPatternInformationValueCodecFieldCompare(v *MutingPatternInformationValueCodec) *func(MutingPatternInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMutingPatternInformationValueCodecFieldContext(v *MutingPatternInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMutingPatternInformationValueCodecFieldDecode(v *MutingPatternInformationValueCodec) *func([]byte, aper.DecodeState) (MutingPatternInformation, error) {
	return &v.decode
}
func BridgeMutingPatternInformationValueCodecFieldEncode(v *MutingPatternInformationValueCodec) *func(MutingPatternInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMutingPatternInformationValueCodecFieldPath(v *MutingPatternInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeMutingPatternInformationValueCodecMethodEncodeBudgetValue(v MutingPatternInformationValueCodec, a0 MutingPatternInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMutingPatternInformationValueCodecMethodEncodeChanged(v MutingPatternInformationValueCodec, a0 MutingPatternInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASDeliveryIndicationAPERValueFieldContext(v *NASDeliveryIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationAPERValueFieldReceived(v *NASDeliveryIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASDeliveryIndicationAPERValueFieldReplay(v *NASDeliveryIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASDeliveryIndicationAPERValueFieldWithoutReplay(v *NASDeliveryIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASDeliveryIndicationFieldExtCount(v *NASDeliveryIndication) *int64   { return &v.extCount }
func BridgeNASDeliveryIndicationFieldExtData(v *NASDeliveryIndication) *[][]byte { return &v.extData }
func BridgeNASDeliveryIndicationFieldExtOrigin(v *NASDeliveryIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNASDeliveryIndicationFieldExtPresent(v *NASDeliveryIndication) *[]bool {
	return &v.extPresent
}
func BridgeNASDeliveryIndicationFieldExtWire(v *NASDeliveryIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNASDeliveryIndicationFieldPerExtPadding(v *NASDeliveryIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNASDeliveryIndicationFieldPerPadding(v *NASDeliveryIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNASDeliveryIndicationFieldProtocolIEsIndef(v *NASDeliveryIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeNASDeliveryIndicationFieldReceived(v *NASDeliveryIndication) *bool { return &v.received }
func BridgeNASDeliveryIndicationFieldReceivedAbsolute(v *NASDeliveryIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeNASDeliveryIndicationFieldReceivedBytes(v *NASDeliveryIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNASDeliveryIndicationFieldReceivedLocation(v *NASDeliveryIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeNASDeliveryIndicationFieldReplay(v *NASDeliveryIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeNASDeliveryIndicationFieldStream(v *NASDeliveryIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeNASDeliveryIndicationFieldWithoutReplay(v *NASDeliveryIndication) *bool {
	return &v.withoutReplay
}
func BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v *NASDeliveryIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERBudgetValue(v *NASDeliveryIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERChanged(v *NASDeliveryIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERChangedValue(v *NASDeliveryIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERLegacy(v *NASDeliveryIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNASDeliveryIndicationMethodMarshalAPERNewValue(v *NASDeliveryIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERPlanned(v *NASDeliveryIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNASDeliveryIndicationMethodMarshalAPERTo(v *NASDeliveryIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNASDeliveryIndicationMethodUnmarshalAPERFrom(v *NASDeliveryIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNASDeliveryIndicationMethodUnmarshalAPERLegacy(v *NASDeliveryIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNASDeliveryIndicationMethodUnmarshalAPERWithOptions(v *NASDeliveryIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNASDeliveryIndicationValueCodecFieldCapture(v *NASDeliveryIndicationValueCodec) *func(NASDeliveryIndication, aper.DecodeState) (NASDeliveryIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeNASDeliveryIndicationValueCodecFieldCompare(v *NASDeliveryIndicationValueCodec) *func(NASDeliveryIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASDeliveryIndicationValueCodecFieldContext(v *NASDeliveryIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASDeliveryIndicationValueCodecFieldDecode(v *NASDeliveryIndicationValueCodec) *func([]byte, aper.DecodeState) (NASDeliveryIndication, error) {
	return &v.decode
}
func BridgeNASDeliveryIndicationValueCodecFieldEncode(v *NASDeliveryIndicationValueCodec) *func(NASDeliveryIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASDeliveryIndicationValueCodecFieldPath(v *NASDeliveryIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASDeliveryIndicationValueCodecMethodEncodeBudgetValue(v NASDeliveryIndicationValueCodec, a0 NASDeliveryIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASDeliveryIndicationValueCodecMethodEncodeChanged(v NASDeliveryIndicationValueCodec, a0 NASDeliveryIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldCodec(v *NASNonDeliveryIndicationCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldGet(v *NASNonDeliveryIndicationCauseIEBinding) *func(*NASNonDeliveryIndicationIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldInfo(v *NASNonDeliveryIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldInject(v *NASNonDeliveryIndicationCauseIEBinding) *func(s14.Cause) NASNonDeliveryIndicationIEValue {
	return &v.inject
}
func BridgeNASNonDeliveryIndicationENBUES1APIDIEBindingFieldCodec(v *NASNonDeliveryIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeNASNonDeliveryIndicationENBUES1APIDIEBindingFieldGet(v *NASNonDeliveryIndicationENBUES1APIDIEBinding) *func(*NASNonDeliveryIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeNASNonDeliveryIndicationENBUES1APIDIEBindingFieldInfo(v *NASNonDeliveryIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeNASNonDeliveryIndicationENBUES1APIDIEBindingFieldInject(v *NASNonDeliveryIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) NASNonDeliveryIndicationIEValue {
	return &v.inject
}
func BridgeNASNonDeliveryIndicationIEContainerAPERValueFieldContext(v *NASNonDeliveryIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEContainerAPERValueFieldReceived(v *NASNonDeliveryIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEContainerAPERValueFieldReplay(v *NASNonDeliveryIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEContainerAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCapture(v *NASNonDeliveryIndicationIEContainerValueCodec) *func(NASNonDeliveryIndicationIEContainer, aper.DecodeState) (NASNonDeliveryIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldCompare(v *NASNonDeliveryIndicationIEContainerValueCodec) *func(NASNonDeliveryIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldContext(v *NASNonDeliveryIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldDecode(v *NASNonDeliveryIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEContainer, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldEncode(v *NASNonDeliveryIndicationIEContainerValueCodec) *func(NASNonDeliveryIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecFieldPath(v *NASNonDeliveryIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationIEContainerValueCodec, a0 NASNonDeliveryIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationIEContainerValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationIEContainerValueCodec, a0 NASNonDeliveryIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationIEFieldAPERValueFieldContext(v *NASNonDeliveryIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEFieldAPERValueFieldReceived(v *NASNonDeliveryIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEFieldAPERValueFieldReplay(v *NASNonDeliveryIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEFieldAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEFieldFieldReceived(v *NASNonDeliveryIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v *NASNonDeliveryIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEFieldFieldStream(v *NASNonDeliveryIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeNASNonDeliveryIndicationIEFieldFieldWithoutReplay(v *NASNonDeliveryIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(v *NASNonDeliveryIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNASNonDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(v *NASNonDeliveryIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCapture(v *NASNonDeliveryIndicationIEFieldValueCodec) *func(NASNonDeliveryIndicationIEField, aper.DecodeState) (NASNonDeliveryIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldCompare(v *NASNonDeliveryIndicationIEFieldValueCodec) *func(NASNonDeliveryIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldContext(v *NASNonDeliveryIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldDecode(v *NASNonDeliveryIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEField, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldEncode(v *NASNonDeliveryIndicationIEFieldValueCodec) *func(NASNonDeliveryIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecFieldPath(v *NASNonDeliveryIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationIEFieldValueCodec, a0 NASNonDeliveryIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationIEFieldValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationIEFieldValueCodec, a0 NASNonDeliveryIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationIETableMethodInfoCause(v NASNonDeliveryIndicationIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeNASNonDeliveryIndicationIETableMethodInfoENBUES1APID(v NASNonDeliveryIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeNASNonDeliveryIndicationIETableMethodInfoMMEUES1APID(v NASNonDeliveryIndicationIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeNASNonDeliveryIndicationIETableMethodInfoNASPDU(v NASNonDeliveryIndicationIETable) s00.FieldInfo {
	return v.infoNASPDU()
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListAPERValueFieldContext(v *NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueERABIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldContext(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecFieldPath(v *NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationIEValueERABIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationIEValueFieldId(v *NASNonDeliveryIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeNASNonDeliveryIndicationIEValueFieldIsOpaque(v *NASNonDeliveryIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeNASNonDeliveryIndicationIEValueFieldOpaque(v *NASNonDeliveryIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeNASNonDeliveryIndicationIEValueFieldReceived(v *NASNonDeliveryIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEValueFieldReplay(v *NASNonDeliveryIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEValueFieldRowCause(v *NASNonDeliveryIndicationIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeNASNonDeliveryIndicationIEValueFieldRowENBUES1APID(v *NASNonDeliveryIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeNASNonDeliveryIndicationIEValueFieldRowMMEUES1APID(v *NASNonDeliveryIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeNASNonDeliveryIndicationIEValueFieldRowNASPDU(v *NASNonDeliveryIndicationIEValue) **s00.NASPDU {
	return &v.rowNASPDU
}
func BridgeNASNonDeliveryIndicationIEValueMethodCaptureSemantics(v NASNonDeliveryIndicationIEValue, a0 aper.SemanticCapture) NASNonDeliveryIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeNASNonDeliveryIndicationIEValueMethodCompareSemantics(v NASNonDeliveryIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeNASNonDeliveryIndicationIEValueMethodDecode(v NASNonDeliveryIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (NASNonDeliveryIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeNASNonDeliveryIndicationIEValueMethodEncode(v NASNonDeliveryIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeNASNonDeliveryIndicationIEValueMethodEncodeFresh(v NASNonDeliveryIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeNASNonDeliveryIndicationIEValueMethodMatchesID(v NASNonDeliveryIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeNASNonDeliveryIndicationIEValueMethodReason(v NASNonDeliveryIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeNASNonDeliveryIndicationIEValueMethodRule(v NASNonDeliveryIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (NASNonDeliveryIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *func(NASNonDeliveryIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v NASNonDeliveryIndicationIEValueProtocolIEContainerListValueCodec, a0 NASNonDeliveryIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNASNonDeliveryIndicationMMEUES1APIDIEBindingFieldCodec(v *NASNonDeliveryIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeNASNonDeliveryIndicationMMEUES1APIDIEBindingFieldGet(v *NASNonDeliveryIndicationMMEUES1APIDIEBinding) *func(*NASNonDeliveryIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeNASNonDeliveryIndicationMMEUES1APIDIEBindingFieldInfo(v *NASNonDeliveryIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeNASNonDeliveryIndicationMMEUES1APIDIEBindingFieldInject(v *NASNonDeliveryIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) NASNonDeliveryIndicationIEValue {
	return &v.inject
}
func BridgeNASNonDeliveryIndicationNASPDUIEBindingFieldCodec(v *NASNonDeliveryIndicationNASPDUIEBinding) *s01.NASPDUValueCodec {
	return &v.codec
}
func BridgeNASNonDeliveryIndicationNASPDUIEBindingFieldGet(v *NASNonDeliveryIndicationNASPDUIEBinding) *func(*NASNonDeliveryIndicationIEValue) (*s00.NASPDU, bool) {
	return &v.get
}
func BridgeNASNonDeliveryIndicationNASPDUIEBindingFieldInfo(v *NASNonDeliveryIndicationNASPDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeNASNonDeliveryIndicationNASPDUIEBindingFieldInject(v *NASNonDeliveryIndicationNASPDUIEBinding) *func(s00.NASPDU) NASNonDeliveryIndicationIEValue {
	return &v.inject
}
func BridgeNBIoTPagingEDRXInformationAPERValueFieldContext(v *NBIoTPagingEDRXInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingEDRXInformationAPERValueFieldReceived(v *NBIoTPagingEDRXInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNBIoTPagingEDRXInformationAPERValueFieldReplay(v *NBIoTPagingEDRXInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNBIoTPagingEDRXInformationAPERValueFieldWithoutReplay(v *NBIoTPagingEDRXInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNBIoTPagingEDRXInformationFieldExtCount(v *NBIoTPagingEDRXInformation) *int64 {
	return &v.extCount
}
func BridgeNBIoTPagingEDRXInformationFieldExtData(v *NBIoTPagingEDRXInformation) *[][]byte {
	return &v.extData
}
func BridgeNBIoTPagingEDRXInformationFieldExtOrigin(v *NBIoTPagingEDRXInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNBIoTPagingEDRXInformationFieldExtPresent(v *NBIoTPagingEDRXInformation) *[]bool {
	return &v.extPresent
}
func BridgeNBIoTPagingEDRXInformationFieldExtWire(v *NBIoTPagingEDRXInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNBIoTPagingEDRXInformationFieldIEExtensionsIndef(v *NBIoTPagingEDRXInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeNBIoTPagingEDRXInformationFieldPerExtPadding(v *NBIoTPagingEDRXInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNBIoTPagingEDRXInformationFieldPerPadding(v *NBIoTPagingEDRXInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNBIoTPagingEDRXInformationFieldReceived(v *NBIoTPagingEDRXInformation) *bool {
	return &v.received
}
func BridgeNBIoTPagingEDRXInformationFieldReceivedAbsolute(v *NBIoTPagingEDRXInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeNBIoTPagingEDRXInformationFieldReceivedBytes(v *NBIoTPagingEDRXInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNBIoTPagingEDRXInformationFieldReceivedLocation(v *NBIoTPagingEDRXInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeNBIoTPagingEDRXInformationFieldReplay(v *NBIoTPagingEDRXInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeNBIoTPagingEDRXInformationFieldStream(v *NBIoTPagingEDRXInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeNBIoTPagingEDRXInformationFieldWithoutReplay(v *NBIoTPagingEDRXInformation) *bool {
	return &v.withoutReplay
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERBudget(v *NBIoTPagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERBudgetValue(v *NBIoTPagingEDRXInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERChanged(v *NBIoTPagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERChangedValue(v *NBIoTPagingEDRXInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERLegacy(v *NBIoTPagingEDRXInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERNewValue(v *NBIoTPagingEDRXInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERPlanned(v *NBIoTPagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNBIoTPagingEDRXInformationMethodMarshalAPERTo(v *NBIoTPagingEDRXInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNBIoTPagingEDRXInformationMethodUnmarshalAPERFrom(v *NBIoTPagingEDRXInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNBIoTPagingEDRXInformationMethodUnmarshalAPERLegacy(v *NBIoTPagingEDRXInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNBIoTPagingEDRXInformationMethodUnmarshalAPERWithOptions(v *NBIoTPagingEDRXInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldCapture(v *NBIoTPagingEDRXInformationValueCodec) *func(NBIoTPagingEDRXInformation, aper.DecodeState) (NBIoTPagingEDRXInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldCompare(v *NBIoTPagingEDRXInformationValueCodec) *func(NBIoTPagingEDRXInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldContext(v *NBIoTPagingEDRXInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldDecode(v *NBIoTPagingEDRXInformationValueCodec) *func([]byte, aper.DecodeState) (NBIoTPagingEDRXInformation, error) {
	return &v.decode
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldEncode(v *NBIoTPagingEDRXInformationValueCodec) *func(NBIoTPagingEDRXInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingEDRXInformationValueCodecFieldPath(v *NBIoTPagingEDRXInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTPagingEDRXInformationValueCodecMethodEncodeBudgetValue(v NBIoTPagingEDRXInformationValueCodec, a0 NBIoTPagingEDRXInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNBIoTPagingEDRXInformationValueCodecMethodEncodeChanged(v NBIoTPagingEDRXInformationValueCodec, a0 NBIoTPagingEDRXInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNGENBAPERValueFieldContext(v *NGENBAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeNGENBAPERValueFieldReceived(v *NGENBAPERValue) *aper.WireSpan         { return &v.received }
func BridgeNGENBAPERValueFieldReplay(v *NGENBAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeNGENBAPERValueFieldWithoutReplay(v *NGENBAPERValue) *bool             { return &v.withoutReplay }
func BridgeNGENBFieldExtCount(v *NGENB) *int64                                   { return &v.extCount }
func BridgeNGENBFieldExtData(v *NGENB) *[][]byte                                 { return &v.extData }
func BridgeNGENBFieldExtOrigin(v *NGENB) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeNGENBFieldExtPresent(v *NGENB) *[]bool                                { return &v.extPresent }
func BridgeNGENBFieldExtWire(v *NGENB) *[]aper.WireSpan                          { return &v.extWire }
func BridgeNGENBFieldIEExtensionsIndef(v *NGENB) *bool                           { return &v.iEExtensionsIndef }
func BridgeNGENBFieldPerExtPadding(v *NGENB) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeNGENBFieldPerPadding(v *NGENB) *aper.FinalPadding                     { return &v.perPadding }
func BridgeNGENBFieldReceived(v *NGENB) *bool                                    { return &v.received }
func BridgeNGENBFieldReceivedAbsolute(v *NGENB) *bool                            { return &v.receivedAbsolute }
func BridgeNGENBFieldReceivedBytes(v *NGENB) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeNGENBFieldReceivedLocation(v *NGENB) *aper.Location                   { return &v.receivedLocation }
func BridgeNGENBFieldReplay(v *NGENB) *aper.Snapshot                             { return &v.replay }
func BridgeNGENBFieldStream(v *NGENB) *aper.WireSpan                             { return &v.stream }
func BridgeNGENBFieldWithoutReplay(v *NGENB) *bool                               { return &v.withoutReplay }
func BridgeNGENBMethodMarshalAPERBudget(v *NGENB, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNGENBMethodMarshalAPERBudgetValue(v *NGENB, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNGENBMethodMarshalAPERChanged(v *NGENB, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNGENBMethodMarshalAPERChangedValue(v *NGENB, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNGENBMethodMarshalAPERLegacy(v *NGENB) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeNGENBMethodMarshalAPERNewValue(v *NGENB, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNGENBMethodMarshalAPERPlanned(v *NGENB, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNGENBMethodMarshalAPERTo(v *NGENB, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNGENBMethodUnmarshalAPERFrom(v *NGENB, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNGENBMethodUnmarshalAPERLegacy(v *NGENB, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNGENBMethodUnmarshalAPERWithOptions(v *NGENB, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNGENBValueCodecFieldCapture(v *NGENBValueCodec) *func(NGENB, aper.DecodeState) (NGENB, aper.Snapshot) {
	return &v.capture
}
func BridgeNGENBValueCodecFieldCompare(v *NGENBValueCodec) *func(NGENB, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNGENBValueCodecFieldContext(v *NGENBValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeNGENBValueCodecFieldDecode(v *NGENBValueCodec) *func([]byte, aper.DecodeState) (NGENB, error) {
	return &v.decode
}
func BridgeNGENBValueCodecFieldEncode(v *NGENBValueCodec) *func(NGENB, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNGENBValueCodecFieldPath(v *NGENBValueCodec) *aper.Path { return &v.path }
func BridgeNGENBValueCodecMethodEncodeBudgetValue(v NGENBValueCodec, a0 NGENB, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNGENBValueCodecMethodEncodeChanged(v NGENBValueCodec, a0 NGENB, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRCGIAPERValueFieldContext(v *NRCGIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeNRCGIAPERValueFieldReceived(v *NRCGIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeNRCGIAPERValueFieldReplay(v *NRCGIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeNRCGIAPERValueFieldWithoutReplay(v *NRCGIAPERValue) *bool             { return &v.withoutReplay }
func BridgeNRCGIFieldExtCount(v *NRCGI) *int64                                   { return &v.extCount }
func BridgeNRCGIFieldExtData(v *NRCGI) *[][]byte                                 { return &v.extData }
func BridgeNRCGIFieldExtOrigin(v *NRCGI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeNRCGIFieldExtPresent(v *NRCGI) *[]bool                                { return &v.extPresent }
func BridgeNRCGIFieldExtWire(v *NRCGI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeNRCGIFieldIEExtensionsIndef(v *NRCGI) *bool                           { return &v.iEExtensionsIndef }
func BridgeNRCGIFieldPerExtPadding(v *NRCGI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeNRCGIFieldPerPadding(v *NRCGI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeNRCGIFieldReceived(v *NRCGI) *bool                                    { return &v.received }
func BridgeNRCGIFieldReceivedAbsolute(v *NRCGI) *bool                            { return &v.receivedAbsolute }
func BridgeNRCGIFieldReceivedBytes(v *NRCGI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeNRCGIFieldReceivedLocation(v *NRCGI) *aper.Location                   { return &v.receivedLocation }
func BridgeNRCGIFieldReplay(v *NRCGI) *aper.Snapshot                             { return &v.replay }
func BridgeNRCGIFieldStream(v *NRCGI) *aper.WireSpan                             { return &v.stream }
func BridgeNRCGIFieldWithoutReplay(v *NRCGI) *bool                               { return &v.withoutReplay }
func BridgeNRCGIMethodMarshalAPERBudget(v *NRCGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERBudgetValue(v *NRCGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERChanged(v *NRCGI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERChangedValue(v *NRCGI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERLegacy(v *NRCGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeNRCGIMethodMarshalAPERNewValue(v *NRCGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERPlanned(v *NRCGI, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERTo(v *NRCGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIMethodUnmarshalAPERFrom(v *NRCGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIMethodUnmarshalAPERLegacy(v *NRCGI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRCGIMethodUnmarshalAPERWithOptions(v *NRCGI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRCGIValueCodecFieldCapture(v *NRCGIValueCodec) *func(NRCGI, aper.DecodeState) (NRCGI, aper.Snapshot) {
	return &v.capture
}
func BridgeNRCGIValueCodecFieldCompare(v *NRCGIValueCodec) *func(NRCGI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRCGIValueCodecFieldContext(v *NRCGIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeNRCGIValueCodecFieldDecode(v *NRCGIValueCodec) *func([]byte, aper.DecodeState) (NRCGI, error) {
	return &v.decode
}
func BridgeNRCGIValueCodecFieldEncode(v *NRCGIValueCodec) *func(NRCGI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCGIValueCodecFieldPath(v *NRCGIValueCodec) *aper.Path { return &v.path }
func BridgeNRCGIValueCodecMethodEncodeBudgetValue(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNRCGIValueCodecMethodEncodeChanged(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRUESecurityCapabilitiesAPERValueFieldContext(v *NRUESecurityCapabilitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESecurityCapabilitiesAPERValueFieldReceived(v *NRUESecurityCapabilitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNRUESecurityCapabilitiesAPERValueFieldReplay(v *NRUESecurityCapabilitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESecurityCapabilitiesAPERValueFieldWithoutReplay(v *NRUESecurityCapabilitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNRUESecurityCapabilitiesFieldExtCount(v *NRUESecurityCapabilities) *int64 {
	return &v.extCount
}
func BridgeNRUESecurityCapabilitiesFieldExtData(v *NRUESecurityCapabilities) *[][]byte {
	return &v.extData
}
func BridgeNRUESecurityCapabilitiesFieldExtOrigin(v *NRUESecurityCapabilities) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNRUESecurityCapabilitiesFieldExtPresent(v *NRUESecurityCapabilities) *[]bool {
	return &v.extPresent
}
func BridgeNRUESecurityCapabilitiesFieldExtWire(v *NRUESecurityCapabilities) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNRUESecurityCapabilitiesFieldIEExtensionsIndef(v *NRUESecurityCapabilities) *bool {
	return &v.iEExtensionsIndef
}
func BridgeNRUESecurityCapabilitiesFieldPerExtPadding(v *NRUESecurityCapabilities) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNRUESecurityCapabilitiesFieldPerPadding(v *NRUESecurityCapabilities) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNRUESecurityCapabilitiesFieldReceived(v *NRUESecurityCapabilities) *bool {
	return &v.received
}
func BridgeNRUESecurityCapabilitiesFieldReceivedAbsolute(v *NRUESecurityCapabilities) *bool {
	return &v.receivedAbsolute
}
func BridgeNRUESecurityCapabilitiesFieldReceivedBytes(v *NRUESecurityCapabilities) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNRUESecurityCapabilitiesFieldReceivedLocation(v *NRUESecurityCapabilities) *aper.Location {
	return &v.receivedLocation
}
func BridgeNRUESecurityCapabilitiesFieldReplay(v *NRUESecurityCapabilities) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESecurityCapabilitiesFieldStream(v *NRUESecurityCapabilities) *aper.WireSpan {
	return &v.stream
}
func BridgeNRUESecurityCapabilitiesFieldWithoutReplay(v *NRUESecurityCapabilities) *bool {
	return &v.withoutReplay
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v *NRUESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudgetValue(v *NRUESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERChanged(v *NRUESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERChangedValue(v *NRUESecurityCapabilities, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERLegacy(v *NRUESecurityCapabilities) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERNewValue(v *NRUESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERPlanned(v *NRUESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNRUESecurityCapabilitiesMethodMarshalAPERTo(v *NRUESecurityCapabilities, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(v *NRUESecurityCapabilities, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERLegacy(v *NRUESecurityCapabilities, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERWithOptions(v *NRUESecurityCapabilities, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(v *NRUESecurityCapabilitiesValueCodec) *func(NRUESecurityCapabilities, aper.DecodeState) (NRUESecurityCapabilities, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(v *NRUESecurityCapabilitiesValueCodec) *func(NRUESecurityCapabilities, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldContext(v *NRUESecurityCapabilitiesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(v *NRUESecurityCapabilitiesValueCodec) *func([]byte, aper.DecodeState) (NRUESecurityCapabilities, error) {
	return &v.decode
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(v *NRUESecurityCapabilitiesValueCodec) *func(NRUESecurityCapabilities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESecurityCapabilitiesValueCodecFieldPath(v *NRUESecurityCapabilitiesValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESecurityCapabilitiesValueCodecMethodEncodeBudgetValue(v NRUESecurityCapabilitiesValueCodec, a0 NRUESecurityCapabilities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNRUESecurityCapabilitiesValueCodecMethodEncodeChanged(v NRUESecurityCapabilitiesValueCodec, a0 NRUESecurityCapabilities, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRUESidelinkAggregateMaximumBitrateAPERValueFieldContext(v *NRUESidelinkAggregateMaximumBitrateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESidelinkAggregateMaximumBitrateAPERValueFieldReceived(v *NRUESidelinkAggregateMaximumBitrateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNRUESidelinkAggregateMaximumBitrateAPERValueFieldReplay(v *NRUESidelinkAggregateMaximumBitrateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESidelinkAggregateMaximumBitrateAPERValueFieldWithoutReplay(v *NRUESidelinkAggregateMaximumBitrateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldExtCount(v *NRUESidelinkAggregateMaximumBitrate) *int64 {
	return &v.extCount
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldExtData(v *NRUESidelinkAggregateMaximumBitrate) *[][]byte {
	return &v.extData
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldExtOrigin(v *NRUESidelinkAggregateMaximumBitrate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldExtPresent(v *NRUESidelinkAggregateMaximumBitrate) *[]bool {
	return &v.extPresent
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldExtWire(v *NRUESidelinkAggregateMaximumBitrate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldIEExtensionsIndef(v *NRUESidelinkAggregateMaximumBitrate) *bool {
	return &v.iEExtensionsIndef
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldPerExtPadding(v *NRUESidelinkAggregateMaximumBitrate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(v *NRUESidelinkAggregateMaximumBitrate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(v *NRUESidelinkAggregateMaximumBitrate) *bool {
	return &v.received
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedAbsolute(v *NRUESidelinkAggregateMaximumBitrate) *bool {
	return &v.receivedAbsolute
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(v *NRUESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(v *NRUESidelinkAggregateMaximumBitrate) *aper.Location {
	return &v.receivedLocation
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldReplay(v *NRUESidelinkAggregateMaximumBitrate) *aper.Snapshot {
	return &v.replay
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldStream(v *NRUESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.stream
}
func BridgeNRUESidelinkAggregateMaximumBitrateFieldWithoutReplay(v *NRUESidelinkAggregateMaximumBitrate) *bool {
	return &v.withoutReplay
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v *NRUESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudgetValue(v *NRUESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERChanged(v *NRUESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERChangedValue(v *NRUESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERLegacy(v *NRUESidelinkAggregateMaximumBitrate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERNewValue(v *NRUESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERPlanned(v *NRUESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERTo(v *NRUESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(v *NRUESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERLegacy(v *NRUESidelinkAggregateMaximumBitrate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERWithOptions(v *NRUESidelinkAggregateMaximumBitrate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *func(NRUESidelinkAggregateMaximumBitrate, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrate, aper.Snapshot) {
	return &v.capture
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *func(NRUESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *func([]byte, aper.DecodeState) (NRUESidelinkAggregateMaximumBitrate, error) {
	return &v.decode
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *func(NRUESidelinkAggregateMaximumBitrate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(v *NRUESidelinkAggregateMaximumBitrateValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeBudgetValue(v NRUESidelinkAggregateMaximumBitrateValueCodec, a0 NRUESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNRUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeChanged(v NRUESidelinkAggregateMaximumBitrateValueCodec, a0 NRUESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRV2XServicesAuthorizedAPERValueFieldContext(v *NRV2XServicesAuthorizedAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRV2XServicesAuthorizedAPERValueFieldReceived(v *NRV2XServicesAuthorizedAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNRV2XServicesAuthorizedAPERValueFieldReplay(v *NRV2XServicesAuthorizedAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNRV2XServicesAuthorizedAPERValueFieldWithoutReplay(v *NRV2XServicesAuthorizedAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNRV2XServicesAuthorizedFieldExtCount(v *NRV2XServicesAuthorized) *int64 {
	return &v.extCount
}
func BridgeNRV2XServicesAuthorizedFieldExtData(v *NRV2XServicesAuthorized) *[][]byte {
	return &v.extData
}
func BridgeNRV2XServicesAuthorizedFieldExtOrigin(v *NRV2XServicesAuthorized) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNRV2XServicesAuthorizedFieldExtPresent(v *NRV2XServicesAuthorized) *[]bool {
	return &v.extPresent
}
func BridgeNRV2XServicesAuthorizedFieldExtWire(v *NRV2XServicesAuthorized) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNRV2XServicesAuthorizedFieldIEExtensionsIndef(v *NRV2XServicesAuthorized) *bool {
	return &v.iEExtensionsIndef
}
func BridgeNRV2XServicesAuthorizedFieldPerExtPadding(v *NRV2XServicesAuthorized) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNRV2XServicesAuthorizedFieldPerPadding(v *NRV2XServicesAuthorized) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNRV2XServicesAuthorizedFieldReceived(v *NRV2XServicesAuthorized) *bool { return &v.received }
func BridgeNRV2XServicesAuthorizedFieldReceivedAbsolute(v *NRV2XServicesAuthorized) *bool {
	return &v.receivedAbsolute
}
func BridgeNRV2XServicesAuthorizedFieldReceivedBytes(v *NRV2XServicesAuthorized) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNRV2XServicesAuthorizedFieldReceivedLocation(v *NRV2XServicesAuthorized) *aper.Location {
	return &v.receivedLocation
}
func BridgeNRV2XServicesAuthorizedFieldReplay(v *NRV2XServicesAuthorized) *aper.Snapshot {
	return &v.replay
}
func BridgeNRV2XServicesAuthorizedFieldStream(v *NRV2XServicesAuthorized) *aper.WireSpan {
	return &v.stream
}
func BridgeNRV2XServicesAuthorizedFieldWithoutReplay(v *NRV2XServicesAuthorized) *bool {
	return &v.withoutReplay
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v *NRV2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudgetValue(v *NRV2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERChanged(v *NRV2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERChangedValue(v *NRV2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERLegacy(v *NRV2XServicesAuthorized) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERNewValue(v *NRV2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERPlanned(v *NRV2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNRV2XServicesAuthorizedMethodMarshalAPERTo(v *NRV2XServicesAuthorized, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(v *NRV2XServicesAuthorized, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERLegacy(v *NRV2XServicesAuthorized, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERWithOptions(v *NRV2XServicesAuthorized, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(v *NRV2XServicesAuthorizedValueCodec) *func(NRV2XServicesAuthorized, aper.DecodeState) (NRV2XServicesAuthorized, aper.Snapshot) {
	return &v.capture
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(v *NRV2XServicesAuthorizedValueCodec) *func(NRV2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldContext(v *NRV2XServicesAuthorizedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(v *NRV2XServicesAuthorizedValueCodec) *func([]byte, aper.DecodeState) (NRV2XServicesAuthorized, error) {
	return &v.decode
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(v *NRV2XServicesAuthorizedValueCodec) *func(NRV2XServicesAuthorized, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRV2XServicesAuthorizedValueCodecFieldPath(v *NRV2XServicesAuthorizedValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRV2XServicesAuthorizedValueCodecMethodEncodeBudgetValue(v NRV2XServicesAuthorizedValueCodec, a0 NRV2XServicesAuthorized, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNRV2XServicesAuthorizedValueCodecMethodEncodeChanged(v NRV2XServicesAuthorizedValueCodec, a0 NRV2XServicesAuthorized, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNotificationCellListAPERValueFieldContext(v *NotificationCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotificationCellListAPERValueFieldReceived(v *NotificationCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNotificationCellListAPERValueFieldReplay(v *NotificationCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNotificationCellListAPERValueFieldWithoutReplay(v *NotificationCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNotificationCellListItemAPERValueFieldContext(v *NotificationCellListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotificationCellListItemAPERValueFieldReceived(v *NotificationCellListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNotificationCellListItemAPERValueFieldReplay(v *NotificationCellListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNotificationCellListItemAPERValueFieldWithoutReplay(v *NotificationCellListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNotificationCellListItemFieldExtCount(v *NotificationCellListItem) *int64 {
	return &v.extCount
}
func BridgeNotificationCellListItemFieldExtData(v *NotificationCellListItem) *[][]byte {
	return &v.extData
}
func BridgeNotificationCellListItemFieldExtOrigin(v *NotificationCellListItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNotificationCellListItemFieldExtPresent(v *NotificationCellListItem) *[]bool {
	return &v.extPresent
}
func BridgeNotificationCellListItemFieldExtWire(v *NotificationCellListItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeNotificationCellListItemFieldPerExtPadding(v *NotificationCellListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNotificationCellListItemFieldPerPadding(v *NotificationCellListItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNotificationCellListItemFieldReceived(v *NotificationCellListItem) *bool {
	return &v.received
}
func BridgeNotificationCellListItemFieldReceivedAbsolute(v *NotificationCellListItem) *bool {
	return &v.receivedAbsolute
}
func BridgeNotificationCellListItemFieldReceivedBytes(v *NotificationCellListItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNotificationCellListItemFieldReceivedLocation(v *NotificationCellListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeNotificationCellListItemFieldReplay(v *NotificationCellListItem) *aper.Snapshot {
	return &v.replay
}
func BridgeNotificationCellListItemFieldStream(v *NotificationCellListItem) *aper.WireSpan {
	return &v.stream
}
func BridgeNotificationCellListItemFieldWithoutReplay(v *NotificationCellListItem) *bool {
	return &v.withoutReplay
}
func BridgeNotificationCellListItemMethodMarshalAPERBudget(v *NotificationCellListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNotificationCellListItemMethodMarshalAPERBudgetValue(v *NotificationCellListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNotificationCellListItemMethodMarshalAPERChanged(v *NotificationCellListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNotificationCellListItemMethodMarshalAPERChangedValue(v *NotificationCellListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNotificationCellListItemMethodMarshalAPERLegacy(v *NotificationCellListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNotificationCellListItemMethodMarshalAPERNewValue(v *NotificationCellListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNotificationCellListItemMethodMarshalAPERPlanned(v *NotificationCellListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNotificationCellListItemMethodMarshalAPERTo(v *NotificationCellListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNotificationCellListItemMethodUnmarshalAPERFrom(v *NotificationCellListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNotificationCellListItemMethodUnmarshalAPERLegacy(v *NotificationCellListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNotificationCellListItemMethodUnmarshalAPERWithOptions(v *NotificationCellListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNotificationCellListItemValueCodecFieldCapture(v *NotificationCellListItemValueCodec) *func(NotificationCellListItem, aper.DecodeState) (NotificationCellListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeNotificationCellListItemValueCodecFieldCompare(v *NotificationCellListItemValueCodec) *func(NotificationCellListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNotificationCellListItemValueCodecFieldContext(v *NotificationCellListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotificationCellListItemValueCodecFieldDecode(v *NotificationCellListItemValueCodec) *func([]byte, aper.DecodeState) (NotificationCellListItem, error) {
	return &v.decode
}
func BridgeNotificationCellListItemValueCodecFieldEncode(v *NotificationCellListItemValueCodec) *func(NotificationCellListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNotificationCellListItemValueCodecFieldPath(v *NotificationCellListItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeNotificationCellListItemValueCodecMethodEncodeBudgetValue(v NotificationCellListItemValueCodec, a0 NotificationCellListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNotificationCellListItemValueCodecMethodEncodeChanged(v NotificationCellListItemValueCodec, a0 NotificationCellListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNotificationCellListValueCodecFieldCapture(v *NotificationCellListValueCodec) *func(NotificationCellList, aper.DecodeState) (NotificationCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeNotificationCellListValueCodecFieldCompare(v *NotificationCellListValueCodec) *func(NotificationCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNotificationCellListValueCodecFieldContext(v *NotificationCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotificationCellListValueCodecFieldDecode(v *NotificationCellListValueCodec) *func([]byte, aper.DecodeState) (NotificationCellList, error) {
	return &v.decode
}
func BridgeNotificationCellListValueCodecFieldEncode(v *NotificationCellListValueCodec) *func(NotificationCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNotificationCellListValueCodecFieldPath(v *NotificationCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeNotificationCellListValueCodecMethodEncodeBudgetValue(v NotificationCellListValueCodec, a0 NotificationCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeNotificationCellListValueCodecMethodEncodeChanged(v NotificationCellListValueCodec, a0 NotificationCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOverloadResponseAPERValueFieldContext(v *OverloadResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadResponseAPERValueFieldReceived(v *OverloadResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOverloadResponseAPERValueFieldReplay(v *OverloadResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOverloadResponseAPERValueFieldWithoutReplay(v *OverloadResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOverloadResponseFieldPerOpenTypePadding(v *OverloadResponse) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeOverloadResponseFieldPerPadding(v *OverloadResponse) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeOverloadResponseFieldReceived(v *OverloadResponse) *bool { return &v.received }
func BridgeOverloadResponseFieldReceivedAbsolute(v *OverloadResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeOverloadResponseFieldReceivedBytes(v *OverloadResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOverloadResponseFieldReceivedLocation(v *OverloadResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeOverloadResponseFieldReplay(v *OverloadResponse) *aper.Snapshot { return &v.replay }
func BridgeOverloadResponseFieldStream(v *OverloadResponse) *aper.WireSpan { return &v.stream }
func BridgeOverloadResponseFieldWithoutReplay(v *OverloadResponse) *bool   { return &v.withoutReplay }
func BridgeOverloadResponseMethodMarshalAPERBudget(v *OverloadResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOverloadResponseMethodMarshalAPERBudgetValue(v *OverloadResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeOverloadResponseMethodMarshalAPERChanged(v *OverloadResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOverloadResponseMethodMarshalAPERChangedValue(v *OverloadResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOverloadResponseMethodMarshalAPERLegacy(v *OverloadResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOverloadResponseMethodMarshalAPERNewValue(v *OverloadResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeOverloadResponseMethodMarshalAPERPlanned(v *OverloadResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeOverloadResponseMethodMarshalAPERTo(v *OverloadResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOverloadResponseMethodUnmarshalAPERFrom(v *OverloadResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOverloadResponseMethodUnmarshalAPERLegacy(v *OverloadResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOverloadResponseMethodUnmarshalAPERWithOptions(v *OverloadResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOverloadResponseValueCodecFieldCapture(v *OverloadResponseValueCodec) *func(OverloadResponse, aper.DecodeState) (OverloadResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadResponseValueCodecFieldCompare(v *OverloadResponseValueCodec) *func(OverloadResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadResponseValueCodecFieldContext(v *OverloadResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadResponseValueCodecFieldDecode(v *OverloadResponseValueCodec) *func([]byte, aper.DecodeState) (OverloadResponse, error) {
	return &v.decode
}
func BridgeOverloadResponseValueCodecFieldEncode(v *OverloadResponseValueCodec) *func(OverloadResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadResponseValueCodecFieldPath(v *OverloadResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadResponseValueCodecMethodEncodeBudgetValue(v OverloadResponseValueCodec, a0 OverloadResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeOverloadResponseValueCodecMethodEncodeChanged(v OverloadResponseValueCodec, a0 OverloadResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePC5FlowBitRatesAPERValueFieldContext(v *PC5FlowBitRatesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5FlowBitRatesAPERValueFieldReceived(v *PC5FlowBitRatesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePC5FlowBitRatesAPERValueFieldReplay(v *PC5FlowBitRatesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePC5FlowBitRatesAPERValueFieldWithoutReplay(v *PC5FlowBitRatesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePC5FlowBitRatesFieldExtCount(v *PC5FlowBitRates) *int64   { return &v.extCount }
func BridgePC5FlowBitRatesFieldExtData(v *PC5FlowBitRates) *[][]byte { return &v.extData }
func BridgePC5FlowBitRatesFieldExtOrigin(v *PC5FlowBitRates) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePC5FlowBitRatesFieldExtPresent(v *PC5FlowBitRates) *[]bool       { return &v.extPresent }
func BridgePC5FlowBitRatesFieldExtWire(v *PC5FlowBitRates) *[]aper.WireSpan { return &v.extWire }
func BridgePC5FlowBitRatesFieldIEExtensionsIndef(v *PC5FlowBitRates) *bool {
	return &v.iEExtensionsIndef
}
func BridgePC5FlowBitRatesFieldPerExtPadding(v *PC5FlowBitRates) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePC5FlowBitRatesFieldPerPadding(v *PC5FlowBitRates) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePC5FlowBitRatesFieldReceived(v *PC5FlowBitRates) *bool         { return &v.received }
func BridgePC5FlowBitRatesFieldReceivedAbsolute(v *PC5FlowBitRates) *bool { return &v.receivedAbsolute }
func BridgePC5FlowBitRatesFieldReceivedBytes(v *PC5FlowBitRates) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePC5FlowBitRatesFieldReceivedLocation(v *PC5FlowBitRates) *aper.Location {
	return &v.receivedLocation
}
func BridgePC5FlowBitRatesFieldReplay(v *PC5FlowBitRates) *aper.Snapshot { return &v.replay }
func BridgePC5FlowBitRatesFieldStream(v *PC5FlowBitRates) *aper.WireSpan { return &v.stream }
func BridgePC5FlowBitRatesFieldWithoutReplay(v *PC5FlowBitRates) *bool   { return &v.withoutReplay }
func BridgePC5FlowBitRatesMethodMarshalAPERBudget(v *PC5FlowBitRates, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePC5FlowBitRatesMethodMarshalAPERBudgetValue(v *PC5FlowBitRates, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePC5FlowBitRatesMethodMarshalAPERChanged(v *PC5FlowBitRates, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePC5FlowBitRatesMethodMarshalAPERChangedValue(v *PC5FlowBitRates, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePC5FlowBitRatesMethodMarshalAPERLegacy(v *PC5FlowBitRates) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePC5FlowBitRatesMethodMarshalAPERNewValue(v *PC5FlowBitRates, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePC5FlowBitRatesMethodMarshalAPERPlanned(v *PC5FlowBitRates, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePC5FlowBitRatesMethodMarshalAPERTo(v *PC5FlowBitRates, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5FlowBitRatesMethodUnmarshalAPERFrom(v *PC5FlowBitRates, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5FlowBitRatesMethodUnmarshalAPERLegacy(v *PC5FlowBitRates, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePC5FlowBitRatesMethodUnmarshalAPERWithOptions(v *PC5FlowBitRates, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePC5FlowBitRatesValueCodecFieldCapture(v *PC5FlowBitRatesValueCodec) *func(PC5FlowBitRates, aper.DecodeState) (PC5FlowBitRates, aper.Snapshot) {
	return &v.capture
}
func BridgePC5FlowBitRatesValueCodecFieldCompare(v *PC5FlowBitRatesValueCodec) *func(PC5FlowBitRates, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5FlowBitRatesValueCodecFieldContext(v *PC5FlowBitRatesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5FlowBitRatesValueCodecFieldDecode(v *PC5FlowBitRatesValueCodec) *func([]byte, aper.DecodeState) (PC5FlowBitRates, error) {
	return &v.decode
}
func BridgePC5FlowBitRatesValueCodecFieldEncode(v *PC5FlowBitRatesValueCodec) *func(PC5FlowBitRates, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5FlowBitRatesValueCodecFieldPath(v *PC5FlowBitRatesValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5FlowBitRatesValueCodecMethodEncodeBudgetValue(v PC5FlowBitRatesValueCodec, a0 PC5FlowBitRates, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePC5FlowBitRatesValueCodecMethodEncodeChanged(v PC5FlowBitRatesValueCodec, a0 PC5FlowBitRates, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
