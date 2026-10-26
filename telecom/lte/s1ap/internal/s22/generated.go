// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s22 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s22

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	big "math/big"
)

// NASNonDeliveryIndicationIEContainer is ProtocolIE-Container {{NASNonDeliveryIndication-IEs}} of TS 36.413: a list of NASNonDeliveryIndicationIEField values.
type NASNonDeliveryIndicationIEContainer []NASNonDeliveryIndicationIEField

// NASNonDeliveryIndicationIEField is ProtocolIE-Field {{NASNonDeliveryIndication-IEs}} of TS 36.413: an information element field.
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
	var zero NASNonDeliveryIndicationIEValue

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

// LocationReportingFailureIndicationIEContainer is ProtocolIE-Container {{LocationReportingFailureIndicationIEs}} of TS 36.413: a list of LocationReportingFailureIndicationIEField values.
type LocationReportingFailureIndicationIEContainer []LocationReportingFailureIndicationIEField

// LocationReportingFailureIndicationIEField is ProtocolIE-Field {{LocationReportingFailureIndicationIEs}} of TS 36.413: an information element field.
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

// LocationReportingFailureIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the LocationReportingFailureIndicationIEs object set of TS 36.413.
type LocationReportingFailureIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) LocationReportingFailureIndicationIEValue

	get func(*LocationReportingFailureIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingFailureIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingFailureIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingFailureIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (LocationReportingFailureIndicationIEField, error) {
	if b.inject == nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingFailureIndicationMMEUES1APIDIEBinding) Get(field *LocationReportingFailureIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LocationReportingFailureIndicationENBUES1APIDIEBinding binds ENBUES1APID to the LocationReportingFailureIndicationIEs object set of TS 36.413.
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

// LocationReportingFailureIndicationCauseIEBinding binds Cause to the LocationReportingFailureIndicationIEs object set of TS 36.413.
type LocationReportingFailureIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) LocationReportingFailureIndicationIEValue

	get func(*LocationReportingFailureIndicationIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Codec() s17.CauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b LocationReportingFailureIndicationCauseIEBinding) New(value s17.Cause,

) (LocationReportingFailureIndicationIEField, error) {
	if b.inject == nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return LocationReportingFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b LocationReportingFailureIndicationCauseIEBinding) Get(field *LocationReportingFailureIndicationIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// NASNonDeliveryIndicationENBUES1APIDIEBinding binds ENBUES1APID to the NASNonDeliveryIndication-IEs object set of TS 36.413.
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

// NASNonDeliveryIndicationCauseIEBinding binds Cause to the NASNonDeliveryIndication-IEs object set of TS 36.413.
type NASNonDeliveryIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) NASNonDeliveryIndicationIEValue

	get func(*NASNonDeliveryIndicationIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b NASNonDeliveryIndicationCauseIEBinding) New(value s17.Cause,

) (NASNonDeliveryIndicationIEField, error) {
	if b.inject == nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return NASNonDeliveryIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return NASNonDeliveryIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b NASNonDeliveryIndicationCauseIEBinding) Get(field *NASNonDeliveryIndicationIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
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

// M1PeriodicReportingValueCodec is the concrete ValueCodec[M1PeriodicReporting].
type M1PeriodicReportingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (M1PeriodicReporting,

		error)
	encode func(M1PeriodicReporting,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(M1PeriodicReporting, aper.DecodeState,

	) (M1PeriodicReporting, aper.Snapshot,

	)
	compare func(M1PeriodicReporting, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1PeriodicReportingValueCodec) New(value M1PeriodicReporting,

) (M1PeriodicReportingAPERValue, error) {
	if c.encode == nil {
		return M1PeriodicReportingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1PeriodicReportingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1PeriodicReportingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1PeriodicReportingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1PeriodicReportingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1PeriodicReportingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1PeriodicReportingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1PeriodicReportingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1PeriodicReportingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1PeriodicReportingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1PeriodicReportingValueCodec) EncodeAPER(value M1PeriodicReportingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c M1PeriodicReportingValueCodec) encodeBudgetValue(value M1PeriodicReporting,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1PeriodicReportingValueCodec) encodeChanged(value M1PeriodicReporting,

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

// M1PeriodicReportingAPERValue is the concrete APERValue[M1PeriodicReporting].
type M1PeriodicReportingAPERValue struct {
	context s00.BridgeCodecContext
	Value   M1PeriodicReporting

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1PeriodicReportingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1PeriodicReportingAPERValue) WithoutReplay() M1PeriodicReportingAPERValue {
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

// LocationReportingFailureIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[LocationReportingFailureIndicationIEValueERABIEContainerList].
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

// LocationReportingFailureIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{LocationReportingFailureIndicationIEs}} of TS 36.413: a list of information element fields.
type LocationReportingFailureIndicationIEValueERABIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEFieldValueCodec is the concrete ValueCodec[LocationReportingFailureIndicationIEField].
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

// LocationReportingFailureIndicationIEContainerValueCodec is the concrete ValueCodec[LocationReportingFailureIndicationIEContainer].
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

// NASNonDeliveryIndicationIEContainerValueCodec is the concrete ValueCodec[NASNonDeliveryIndicationIEContainer].
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

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList].
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

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{LocationReportingFailureIndicationIEs}} of TS 36.413: a list of information element fields.
type LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[LocationReportingFailureIndicationIEValueProtocolIEContainerList].
type LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolIEContainerList, error)
	encode  func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) New(value LocationReportingFailureIndicationIEValueProtocolIEContainerList) (LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value LocationReportingFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value LocationReportingFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportingFailureIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {LocationReportingFailureIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type LocationReportingFailureIndicationIEValueProtocolIEContainerList []LocationReportingFailureIndicationIEValueProtocolIESingleContainer

// LocationReportingFailureIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[LocationReportingFailureIndicationIEValueERABIEContainerList].
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

// LocationReportingFailureIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{LocationReportingFailureIndicationIEs}} of TS 36.413: a single information element field.
type LocationReportingFailureIndicationIEValueProtocolIESingleContainer = LocationReportingFailureIndicationIEField

// LocationReportingFailureIndicationIEFieldAPERValue is the concrete APERValue[LocationReportingFailureIndicationIEField].
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

// LocationReportingFailureIndicationIEContainerAPERValue is the concrete APERValue[LocationReportingFailureIndicationIEContainer].
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

// NASNonDeliveryIndicationIEContainerAPERValue is the concrete APERValue[NASNonDeliveryIndicationIEContainer].
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

// LocationReportingFailureIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[LocationReportingFailureIndicationIEValueProtocolErrorIEContainerList].
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

// LocationReportingFailureIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[LocationReportingFailureIndicationIEValueProtocolIEContainerList].
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
func BridgeCaptureS1APEventL1LoggedMDTConfig(v *EventL1LoggedMDTConfig, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APMeasurementThresholdL1LoggedMDT(&v.L1Threshold, s)
	s00.BridgeCaptureS1APHysteresis(&v.Hysteresis, s)
	s00.BridgeCaptureS1APTimeToTrigger(&v.TimeToTrigger, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEventL1LoggedMDTConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s08.BridgeCompareS1APTimeToTrigger(&v.TimeToTrigger, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEventL1LoggedMDTConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
				s15.BridgeEventTriggerExtIEValueCaptureS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
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
				s15.BridgeEventTriggerExtIEValueCompareS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
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
	s15.BridgeGERANCellIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APGERANCellID(v *GERANCellID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APLAI(&v.LAI, s)
	s08.BridgeCompareS1APRAC(&v.RAC, s)
	s02.BridgeCompareS1APCI(&v.CI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeGERANCellIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
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
	s16.BridgeLAIExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLAI(v *LAI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s02.BridgeCompareS1APLAC(&v.LAC, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeLAIExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeLTENTNTAIInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLTENTNTAIInformation(v *LTENTNTAIInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APPLMNidentity(&v.ServingPLMN, s)
	s08.BridgeCompareS1APTACListInLTENTN(&v.TACListInLTENTN, s)
	{
		f := s.Begin()
		s.Bool(v.UELocationDerivedTAC == nil)
		if v.UELocationDerivedTAC != nil {
			s08.BridgeCompareS1APTAC(v.UELocationDerivedTAC, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s16.BridgeLTENTNTAIInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeListeningSubframePatternExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeListeningSubframePatternExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
func BridgeCaptureS1APM1PeriodicReporting(v *M1PeriodicReporting, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APReportIntervalMDT(&v.ReportInterval, s)
	s00.BridgeCaptureS1APReportAmountMDT(&v.ReportAmount, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeM1PeriodicReportingExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APM1PeriodicReporting(v *M1PeriodicReporting, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APReportIntervalMDT(&v.ReportInterval, s)
	s08.BridgeCompareS1APReportAmountMDT(&v.ReportAmount, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeM1PeriodicReportingExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APM1ThresholdEventA2(v *M1ThresholdEventA2, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APMeasurementThresholdA2(&v.MeasurementThreshold, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeM1ThresholdEventA2ExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM1ThresholdEventA2ExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM3ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM3ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM4ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM4ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM5ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM5ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM6ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM6ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM7ConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeM7ConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeMBSFNResultToLogInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeMBSFNResultToLogInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s16.BridgeMMECPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMECPRelocationIndication(v *MMECPRelocationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s16.BridgeMMECPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
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
				s08.BridgeCompareS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s08.BridgeCompareS1APThresholdRSRQ(v.ThresholdRSRQ, s)
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
				s16.BridgeMeasurementThresholdL1LoggedMDTExtIEValueCaptureS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
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
				s08.BridgeCompareS1APThresholdRSRP(v.ThresholdRSRP, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		{
			f := s.Begin()
			s.Bool(v.ThresholdRSRQ == nil)
			if v.ThresholdRSRQ != nil {
				s08.BridgeCompareS1APThresholdRSRQ(v.ThresholdRSRQ, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		{
			f := s.Begin()
			s.Bool(v.ChoiceExtensions == nil)
			if v.ChoiceExtensions != nil {
				s16.BridgeMeasurementThresholdL1LoggedMDTExtIEValueCompareS1APProtocolIESingleContainer(v.ChoiceExtensions, s)
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
				s21.BridgeCaptureS1APEUTRANResponse(v.EUTRANResponse, s)
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
				s18.BridgeCaptureS1APEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, s)
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
				s21.BridgeCompareS1APEUTRANResponse(v.EUTRANResponse, s)
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
				s18.BridgeCompareS1APEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, s)
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
	s16.BridgeMutingPatternInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s16.BridgeMutingPatternInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APNASDeliveryIndication(v *NASDeliveryIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s16.BridgeNASDeliveryIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNASDeliveryIndication(v *NASDeliveryIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s16.BridgeNASDeliveryIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
	IEExtensions      s11.GERANCellIDExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
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
	IEExtensions      s10.EventL1LoggedMDTConfigExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	ChoiceExtensions       *s10.EventTriggerExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
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
	IEExtensions      s11.LAIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.ListeningSubframePatternExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                           `asn1:"-" json:"-"`
	extCount          int64                                          `asn1:"-" json:"-"`
	extPresent        []bool                                         `asn1:"-" json:"-"`
	extData           [][]byte                                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
	IEExtensions         s11.LTENTNTAIInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                       `asn1:"-" json:"-"`
	extCount             int64                                      `asn1:"-" json:"-"`
	extPresent           []bool                                     `asn1:"-" json:"-"`
	extData              [][]byte                                   `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
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
	IEExtensions      s11.M3ConfigurationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.M4ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.M5ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.M6ConfigurationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.M7ConfigurationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s11.MBSFNResultToLogInfoExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	ChoiceExtensions   *s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer `json:"ChoiceExtensions,omitempty"`
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
	IEExtensions        s12.MutingPatternInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                           `asn1:"-" json:"-"`
	extCount            int64                                          `asn1:"-" json:"-"`
	extPresent          []bool                                         `asn1:"-" json:"-"`
	extData             [][]byte                                       `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// M1PeriodicReporting represents the ASN.1 type M1PeriodicReporting (SEQUENCE).
type M1PeriodicReporting struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	ReportInterval    s00.ReportIntervalMDT                     `asn1:"tag:0,context,implicit"`
	ReportAmount      s00.ReportAmountMDT                       `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.M1PeriodicReportingExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                      `asn1:"-" json:"-"`
	extCount          int64                                     `asn1:"-" json:"-"`
	extPresent        []bool                                    `asn1:"-" json:"-"`
	extData           [][]byte                                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                    `asn1:"-" json:"-"`
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
	IEExtensions         s11.M1ThresholdEventA2ExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                     `asn1:"-" json:"-"`
	extCount             int64                                    `asn1:"-" json:"-"`
	extPresent           []bool                                   `asn1:"-" json:"-"`
	extData              [][]byte                                 `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
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
				if err := s11.BridgeGERANCellIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes GERANCellID from APER format.
func (v *GERANCellID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *GERANCellID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = GERANCellID{}
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
		tmp_ieextensions := make(s11.GERANCellIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.GERANCellIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeGERANCellIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := v.L1Threshold.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding l1Threshold: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Hysteresis), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(30), false); err != nil {
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
				if err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes EventL1LoggedMDTConfig from APER format.
func (v *EventL1LoggedMDTConfig) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EventL1LoggedMDTConfig) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	bb.EnterComponent("EventL1LoggedMDTConfig")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	padding, err := aper.CaptureFinalBits(bb, "EventL1LoggedMDTConfig")
	if err != nil {
		return runtime.WrapDecodePath(err, "EventL1LoggedMDTConfig")
	}
	v.perPadding = padding
	return nil
}
func (v *EventL1LoggedMDTConfig) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EventL1LoggedMDTConfig{}
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
	toleranceMark_l1threshold := bb.EnterComponent("L1Threshold")
	if err := v.L1Threshold.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "L1Threshold")
	}
	bb.LeaveComponent(toleranceMark_l1threshold)
	val_hysteresis, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(30), false)
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.EventL1LoggedMDTConfigExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.EventL1LoggedMDTConfigExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeEventL1LoggedMDTConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		if err := s10.BridgeEventTriggerExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *EventTrigger) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EventTrigger")
	}
	bb.EnterComponent("EventTrigger")
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
		toleranceMark_choiceextensions := bb.EnterComponent("ChoiceExtensions")
		var dec_choiceextensions s10.EventTriggerExtIEValueProtocolIESingleContainer
		if err := s10.BridgeEventTriggerExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
		bb.LeaveComponent(toleranceMark_choiceextensions)
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
				if err := s11.BridgeLAIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LAI from APER format.
func (v *LAI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *LAI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LAI{}
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
	val_lac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "LAC")
	}
	v.LAC = s00.LAC(val_lac)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.LAIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.LAIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeLAIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ListeningSubframePattern from APER format.
func (v *ListeningSubframePattern) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ListeningSubframePattern) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ListeningSubframePattern{}
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
		tmp_ieextensions := make(s11.ListeningSubframePatternExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.ListeningSubframePatternExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeListeningSubframePatternExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *LoggedMDTTrigger) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMDTTrigger")
	}
	bb.EnterComponent("LoggedMDTTrigger")
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
				if err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LTENTNTAIInformation from APER format.
func (v *LTENTNTAIInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *LTENTNTAIInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LTENTNTAIInformation{}
	var extAdditions aper.ExtensionAdditions
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
		tmp_ieextensions := make(s11.LTENTNTAIInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.LTENTNTAIInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeLTENTNTAIInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M3Configuration from APER format.
func (v *M3Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M3Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	bb.EnterComponent("M3Configuration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M3Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M3Configuration")
	}
	v.perPadding = padding
	return nil
}
func (v *M3Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M3Configuration{}
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
	val_m3period, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 7, Path: "M3period"})
	if err != nil {
		return runtime.WrapDecodePath(err, "M3period")
	}
	v.M3period = s00.M3period(val_m3period)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M3ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M3ConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM3ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M4Configuration from APER format.
func (v *M4Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M4Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	bb.EnterComponent("M4Configuration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M4Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M4Configuration")
	}
	v.perPadding = padding
	return nil
}
func (v *M4Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M4Configuration{}
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M4ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M4ConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM4ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M5Configuration from APER format.
func (v *M5Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M5Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	bb.EnterComponent("M5Configuration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M5Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M5Configuration")
	}
	v.perPadding = padding
	return nil
}
func (v *M5Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M5Configuration{}
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M5ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M5ConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM5ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M6Configuration from APER format.
func (v *M6Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M6Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	bb.EnterComponent("M6Configuration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M6Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M6Configuration")
	}
	v.perPadding = padding
	return nil
}
func (v *M6Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M6Configuration{}
	var extAdditions aper.ExtensionAdditions
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M6ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M6ConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM6ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M7Configuration from APER format.
func (v *M7Configuration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M7Configuration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	bb.EnterComponent("M7Configuration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	padding, err := aper.CaptureFinalBits(bb, "M7Configuration")
	if err != nil {
		return runtime.WrapDecodePath(err, "M7Configuration")
	}
	v.perPadding = padding
	return nil
}
func (v *M7Configuration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M7Configuration{}
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M7ConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M7ConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM7ConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeBoolean(bb, v.MBSFNAreaId != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.MBSFNAreaId != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MBSFNAreaId), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
				if err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MBSFNResultToLogInfo from APER format.
func (v *MBSFNResultToLogInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MBSFNResultToLogInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	bb.EnterComponent("MBSFNResultToLogInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "MBSFNResultToLogInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNResultToLogInfo")
	}
	v.perPadding = padding
	return nil
}
func (v *MBSFNResultToLogInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MBSFNResultToLogInfo{}
	var extAdditions aper.ExtensionAdditions
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
		val_mbsfnareaid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.MBSFNResultToLogInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.MBSFNResultToLogInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeMBSFNResultToLogInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *MDTModeExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MDTModeExtension")
	}
	bb.EnterComponent("MDTModeExtension")
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
	val_id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(val_id)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	toleranceMark_value := bb.EnterComponent("Value")
	openData_value, err := aper.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	bb.LeaveComponent(toleranceMark_value)
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
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRP), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRP: %w", err)
		}
	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		if v.ThresholdRSRQ == nil {
			return fmt.Errorf("choice alternative threshold-RSRQ is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRQ), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false); err != nil {
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
func (v *MeasurementThresholdA2) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdA2")
	}
	bb.EnterComponent("MeasurementThresholdA2")
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
		val_thresholdrsrp, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRP")
		}
		tmp_thresholdrsrp := s00.ThresholdRSRP(val_thresholdrsrp)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrp); err != nil {
			return err
		}
		v.ThresholdRSRP = (*s00.ThresholdRSRP)(bb.OwnInt64(int64(tmp_thresholdrsrp)))

	case s00.MeasurementThresholdA2ChoiceThresholdRSRQ:
		val_thresholdrsrq, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false)
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
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRP), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRP: %w", err)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		if v.ThresholdRSRQ == nil {
			return fmt.Errorf("choice alternative threshold-RSRQ is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ThresholdRSRQ), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false); err != nil {
			return fmt.Errorf("encoding threshold-RSRQ: %w", err)
		}
	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		if v.ChoiceExtensions == nil {
			return fmt.Errorf("choice alternative choice-Extensions is nil")
		}
		if err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodMarshalAPERTo(v.ChoiceExtensions, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *MeasurementThresholdL1LoggedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThresholdL1LoggedMDT")
	}
	bb.EnterComponent("MeasurementThresholdL1LoggedMDT")
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
		val_thresholdrsrp, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(97), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRP")
		}
		tmp_thresholdrsrp := s00.ThresholdRSRP(val_thresholdrsrp)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrp); err != nil {
			return err
		}
		v.ThresholdRSRP = (*s00.ThresholdRSRP)(bb.OwnInt64(int64(tmp_thresholdrsrp)))

	case s00.MeasurementThresholdL1LoggedMDTChoiceThresholdRSRQ:
		val_thresholdrsrq, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(34), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ThresholdRSRQ")
		}
		tmp_thresholdrsrq := s00.ThresholdRSRQ(val_thresholdrsrq)
		if err := aper.ChargeValue(bb, tmp_thresholdrsrq); err != nil {
			return err
		}
		v.ThresholdRSRQ = (*s00.ThresholdRSRQ)(bb.OwnInt64(int64(tmp_thresholdrsrq)))

	case s00.MeasurementThresholdL1LoggedMDTChoiceChoiceExtensions:
		toleranceMark_choiceextensions := bb.EnterComponent("ChoiceExtensions")
		var dec_choiceextensions s12.MeasurementThresholdL1LoggedMDTExtIEValueProtocolIESingleContainer
		if err := s12.BridgeMeasurementThresholdL1LoggedMDTExtIEFieldMethodUnmarshalAPERFrom(&dec_choiceextensions, bb); err != nil {
			return runtime.WrapDecodePath(err, "ChoiceExtensions")
		}
		if err := aper.ChargeValue(bb, dec_choiceextensions); err != nil {
			return err
		}
		v.ChoiceExtensions = &dec_choiceextensions
		bb.LeaveComponent(toleranceMark_choiceextensions)
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
				if err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MutingPatternInformation from APER format.
func (v *MutingPatternInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MutingPatternInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	bb.EnterComponent("MutingPatternInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "MutingPatternInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "MutingPatternInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *MutingPatternInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MutingPatternInformation{}
	var extAdditions aper.ExtensionAdditions
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.MutingPatternInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.MutingPatternInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeMutingPatternInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes M1PeriodicReporting to APER format.
func (v *M1PeriodicReporting) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *M1PeriodicReporting) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.ReportInterval), 13, false); err != nil {
		return fmt.Errorf("encoding reportInterval: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.ReportAmount), 8, false); err != nil {
		return fmt.Errorf("encoding reportAmount: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M1PeriodicReporting from APER format.
func (v *M1PeriodicReporting) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M1PeriodicReporting) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M1PeriodicReporting")
	}
	bb.EnterComponent("M1PeriodicReporting")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M1PeriodicReporting")
	}
	padding, err := aper.CaptureFinalBits(bb, "M1PeriodicReporting")
	if err != nil {
		return runtime.WrapDecodePath(err, "M1PeriodicReporting")
	}
	v.perPadding = padding
	return nil
}
func (v *M1PeriodicReporting) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1PeriodicReporting{}
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
	val_reportinterval, err := aper.DecodeEnumeratedAligned(bb, 13, false, aper.EnumerationSource{KnownExtensions: 0, Path: "ReportInterval"})
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportInterval")
	}
	v.ReportInterval = s00.ReportIntervalMDT(val_reportinterval)
	val_reportamount, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "ReportAmount"})
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportAmount")
	}
	v.ReportAmount = s00.ReportAmountMDT(val_reportamount)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M1PeriodicReportingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M1PeriodicReportingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM1PeriodicReportingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes M1ThresholdEventA2 from APER format.
func (v *M1ThresholdEventA2) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *M1ThresholdEventA2) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	bb.EnterComponent("M1ThresholdEventA2")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	padding, err := aper.CaptureFinalBits(bb, "M1ThresholdEventA2")
	if err != nil {
		return runtime.WrapDecodePath(err, "M1ThresholdEventA2")
	}
	v.perPadding = padding
	return nil
}
func (v *M1ThresholdEventA2) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = M1ThresholdEventA2{}
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
	toleranceMark_measurementthreshold := bb.EnterComponent("MeasurementThreshold")
	if err := v.MeasurementThreshold.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementThreshold")
	}
	bb.LeaveComponent(toleranceMark_measurementthreshold)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.M1ThresholdEventA2ExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.M1ThresholdEventA2ExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeM1ThresholdEventA2ExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *EventL1LoggedMDTConfig) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventL1LoggedMDTConfig", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EventTrigger", v.receivedLocation, v.perPadding)
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
func (v *GERANCellID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "GERANCellID", v.receivedLocation, v.perPadding)
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
func (v *LAI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LAI", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LTENTNTAIInformation", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedGERANCellInformation", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ListeningSubframePattern", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LoggedMDTTrigger) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LoggedMDTTrigger", v.receivedLocation, v.perPadding)
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
func (v *M1PeriodicReporting) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M1PeriodicReporting", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "M1PeriodicReporting", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v M1PeriodicReporting) WithoutReplay() M1PeriodicReporting {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero M1PeriodicReporting
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *M1ThresholdEventA2) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M1ThresholdEventA2", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M3Configuration", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M4Configuration", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M5Configuration", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M6Configuration", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "M7Configuration", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNResultToLogInfo", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MDTModeExtension", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementThresholdA2", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementThresholdL1LoggedMDT", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MutingPatternInformation", v.receivedLocation, v.perPadding)
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

// Extensions returns owned unknown sequence additions.
func (v *M1PeriodicReporting) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *M1PeriodicReporting) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M1PeriodicReporting.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M1PeriodicReporting.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *M1PeriodicReporting) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("M1PeriodicReporting.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("M1PeriodicReporting.Extensions[%d]", index))
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
func (v *M1PeriodicReporting) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "M1PeriodicReporting")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *M1PeriodicReporting) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "M1PeriodicReporting")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APM1PeriodicReporting(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "M1PeriodicReporting")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "M1PeriodicReporting")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *M1PeriodicReporting) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "M1PeriodicReporting")
}
func (v *M1PeriodicReporting) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "M1PeriodicReporting")
}
func (v *M1PeriodicReporting) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APM1PeriodicReporting(v, &s)
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
func (v *M1PeriodicReporting) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *M1PeriodicReporting) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *M1PeriodicReporting) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "M1PeriodicReporting")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded M1PeriodicReporting
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APM1PeriodicReporting(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = M1PeriodicReporting{}
		return report, aper.OperationError(err, "M1PeriodicReporting")
	}
	*v = decoded
	return report, aper.OperationError(nil, "M1PeriodicReporting")
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

// NASDeliveryIndication represents the ASN.1 type NASDeliveryIndication (SEQUENCE).
type NASDeliveryIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.NASDeliveryIndicationIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s11.MMECPRelocationIndicationIEContainer `asn1:"tag:0,context,implicit"`
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s12.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NASDeliveryIndication from APER format.
func (v *NASDeliveryIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NASDeliveryIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	bb.EnterComponent("NASDeliveryIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "NASDeliveryIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "NASDeliveryIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *NASDeliveryIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NASDeliveryIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.NASDeliveryIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.NASDeliveryIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeNASDeliveryIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMECPRelocationIndication from APER format.
func (v *MMECPRelocationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MMECPRelocationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	bb.EnterComponent("MMECPRelocationIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMECPRelocationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMECPRelocationIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *MMECPRelocationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMECPRelocationIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s11.MMECPRelocationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s11.MMECPRelocationIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *MMECPRelocationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMECPRelocationIndication", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "NASDeliveryIndication", v.receivedLocation, v.perPadding)
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
	EUTRANResponse     *s21.EUTRANResponse                            `json:"EUTRANResponse,omitempty"`
	UTRANResponse      []byte                                         `json:"UTRANResponse,omitzero"`
	GERANResponse      []byte                                         `json:"GERANResponse,omitzero"`
	EHRPD              *s18.EHRPDMultiSectorLoadReportingResponseItem `json:"EHRPD,omitempty"`
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
			if err := s18.BridgeEHRPDMultiSectorLoadReportingResponseItemMethodMarshalAPERTo(v.EHRPD, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eHRPD: %w", err)
			}
		default:
			return fmt.Errorf("unknown MultiCellLoadReportingResponseItem extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s08.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
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
		if err := s21.BridgeEUTRANResponseMethodMarshalAPERTo(v.EUTRANResponse, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *MultiCellLoadReportingResponseItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingResponseItem")
	}
	bb.EnterComponent("MultiCellLoadReportingResponseItem")
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
			toleranceMark_ehrpd := inner.EnterComponent("EHRPD")
			var dec_ehrpd s18.EHRPDMultiSectorLoadReportingResponseItem
			if err := s18.BridgeEHRPDMultiSectorLoadReportingResponseItemMethodUnmarshalAPERFrom(&dec_ehrpd, inner); err != nil {
				return runtime.WrapDecodePath(err, "EHRPD")
			}
			if err := aper.ChargeValue(inner, dec_ehrpd); err != nil {
				return err
			}
			v.EHRPD = &dec_ehrpd
			inner.LeaveComponent(toleranceMark_ehrpd)
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
	case s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse:
		toleranceMark_eutranresponse := bb.EnterComponent("EUTRANResponse")
		var dec_eutranresponse s21.EUTRANResponse
		if err := s21.BridgeEUTRANResponseMethodUnmarshalAPERFrom(&dec_eutranresponse, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MultiCellLoadReportingResponseItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MultiCellLoadReportingResponseItem", v.receivedLocation, v.perPadding)
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

type LocationReportingFailureIndicationIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowMMEUES1APID *s00.MMEUES1APID
	rowENBUES1APID *s00.ENBUES1APID
	rowCause       *s17.Cause
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
func (v *LocationReportingFailureIndicationIEValue) AsCause() (*s17.Cause, bool) {
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
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.Cause
		child := scope
		if err := s17.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s17.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s17.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCauseFieldReceivedBytes(&value))
		*s17.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "LocationReportingFailureIndicationIEValue:", v.id)
	}
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
	rowCause       *s17.Cause
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
func (v *NASNonDeliveryIndicationIEValue) AsCause() (*s17.Cause, bool) {
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
		var value s17.Cause
		child := scope
		if err := s17.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s17.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s17.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCauseFieldReceivedBytes(&value))
		*s17.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "NASNonDeliveryIndicationIEValue:", v.id)
	}
}

type LocationReportingFailureIndicationIETable struct{}

func LocationReportingFailureIndicationIEs() LocationReportingFailureIndicationIETable {
	return LocationReportingFailureIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of LocationReportingFailureIndicationIETable.
func (LocationReportingFailureIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingFailureIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by LocationReportingFailureIndicationIETable.
func (LocationReportingFailureIndicationIETable) Table() s00.LocationReportingFailureIndicationIEValueIETable {
	return func() s00.LocationReportingFailureIndicationIEValueIETable {
		sealed := s00.LocationReportingFailureIndicationIEValueIETable{}
		*s00.BridgeLocationReportingFailureIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (LocationReportingFailureIndicationIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingFailureIndicationIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of LocationReportingFailureIndicationIETable.
func (t LocationReportingFailureIndicationIETable) MMEUES1APID() LocationReportingFailureIndicationMMEUES1APIDIEBinding {
	return LocationReportingFailureIndicationMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero LocationReportingFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding LocationReportingFailureIndicationIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) LocationReportingFailureIndicationIEValue {
			return LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *LocationReportingFailureIndicationIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (LocationReportingFailureIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingFailureIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of LocationReportingFailureIndicationIETable.
func (t LocationReportingFailureIndicationIETable) ENBUES1APID() LocationReportingFailureIndicationENBUES1APIDIEBinding {
	return LocationReportingFailureIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero LocationReportingFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding LocationReportingFailureIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) LocationReportingFailureIndicationIEValue {
			return LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *LocationReportingFailureIndicationIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (LocationReportingFailureIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: LocationReportingFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "LocationReportingFailureIndicationIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of LocationReportingFailureIndicationIETable.
func (t LocationReportingFailureIndicationIETable) Cause() LocationReportingFailureIndicationCauseIEBinding {
	return LocationReportingFailureIndicationCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero LocationReportingFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding LocationReportingFailureIndicationIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s17.Cause, options aper.DecodeState) (s17.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s17.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s17.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.Cause) LocationReportingFailureIndicationIEValue {
			return LocationReportingFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *LocationReportingFailureIndicationIEValue) (*s17.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in LocationReportingFailureIndicationIETable.
func (t LocationReportingFailureIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (LocationReportingFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return LocationReportingFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return LocationReportingFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return LocationReportingFailureIndicationIEField{Id: id, Criticality: criticality, Value: LocationReportingFailureIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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

// M1PeriodicReportingCodec binds the complete source value type.
func M1PeriodicReportingCodec() M1PeriodicReportingValueCodec {
	return M1PeriodicReportingValueCodec{path: "M1PeriodicReporting", decode: func(data []byte, options aper.DecodeState) (M1PeriodicReporting, error) {
		var value M1PeriodicReporting
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return M1PeriodicReporting{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value M1PeriodicReporting, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v M1PeriodicReporting, options aper.DecodeState) (M1PeriodicReporting, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APM1PeriodicReporting(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v M1PeriodicReporting, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APM1PeriodicReporting(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M1PeriodicReporting"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
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
	return s21.CellTrafficTraceIEs().MMEUES1APID().Codec()
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
func BridgeEventTriggerMethodMarshalAPERBudget(v *EventTrigger, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeGERANCellIDMethodMarshalAPERTo(v *GERANCellID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeGERANCellIDMethodUnmarshalAPERFrom(v *GERANCellID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLAIFieldPerPadding(v *LAI) *aper.FinalPadding   { return &v.perPadding }
func BridgeLAIFieldReceived(v *LAI) *bool                  { return &v.received }
func BridgeLAIFieldReceivedBytes(v *LAI) *aper.WireSpan    { return &v.receivedBytes }
func BridgeLAIFieldReceivedLocation(v *LAI) *aper.Location { return &v.receivedLocation }
func BridgeLAIMethodMarshalAPERBudget(v *LAI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLAIMethodMarshalAPERTo(v *LAI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLAIMethodUnmarshalAPERFrom(v *LAI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeLTENTNTAIInformationFieldPerPadding(v *LTENTNTAIInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLTENTNTAIInformationFieldReceived(v *LTENTNTAIInformation) *bool { return &v.received }
func BridgeLTENTNTAIInformationFieldReceivedBytes(v *LTENTNTAIInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLTENTNTAIInformationFieldReceivedLocation(v *LTENTNTAIInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v *LTENTNTAIInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(v *LTENTNTAIInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERBudget(v *LastVisitedGERANCellInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedGERANCellInformationMethodMarshalAPERTo(v *LastVisitedGERANCellInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedGERANCellInformationMethodUnmarshalAPERFrom(v *LastVisitedGERANCellInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeListeningSubframePatternMethodMarshalAPERTo(v *ListeningSubframePattern, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeListeningSubframePatternMethodUnmarshalAPERFrom(v *ListeningSubframePattern, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeLocationReportingFailureIndicationIEFieldFieldReplay(v *LocationReportingFailureIndicationIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeLocationReportingFailureIndicationIEValueFieldId(v *LocationReportingFailureIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeLocationReportingFailureIndicationIEValueFieldIsOpaque(v *LocationReportingFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeLocationReportingFailureIndicationIEValueFieldOpaque(v *LocationReportingFailureIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeLocationReportingFailureIndicationIEValueFieldRowCause(v *LocationReportingFailureIndicationIEValue) **s17.Cause {
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
func BridgeLocationReportingFailureIndicationIEValueMethodMatchesID(v LocationReportingFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeLocationReportingFailureIndicationIEValueMethodRule(v LocationReportingFailureIndicationIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (LocationReportingFailureIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(LocationReportingFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *LocationReportingFailureIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggedMDTTriggerFieldPerPadding(v *LoggedMDTTrigger) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeLoggedMDTTriggerFieldReceived(v *LoggedMDTTrigger) *bool { return &v.received }
func BridgeLoggedMDTTriggerFieldReceivedBytes(v *LoggedMDTTrigger) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLoggedMDTTriggerFieldReceivedLocation(v *LoggedMDTTrigger) *aper.Location {
	return &v.receivedLocation
}
func BridgeLoggedMDTTriggerMethodMarshalAPERBudget(v *LoggedMDTTrigger, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLoggedMDTTriggerMethodUnmarshalAPERFrom(v *LoggedMDTTrigger, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeM1PeriodicReportingMethodMarshalAPERTo(v *M1PeriodicReporting, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM1PeriodicReportingMethodUnmarshalAPERFrom(v *M1PeriodicReporting, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM1ThresholdEventA2MethodMarshalAPERTo(v *M1ThresholdEventA2, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeM1ThresholdEventA2MethodUnmarshalAPERFrom(v *M1ThresholdEventA2, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeM3ConfigurationFieldPerPadding(v *M3Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM3ConfigurationFieldReceived(v *M3Configuration) *bool { return &v.received }
func BridgeM3ConfigurationFieldReceivedBytes(v *M3Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM3ConfigurationFieldReceivedLocation(v *M3Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM3ConfigurationMethodMarshalAPERBudget(v *M3Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM3ConfigurationMethodUnmarshalAPERFrom(v *M3Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeM4ConfigurationFieldPerPadding(v *M4Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM4ConfigurationFieldReceived(v *M4Configuration) *bool { return &v.received }
func BridgeM4ConfigurationFieldReceivedBytes(v *M4Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM4ConfigurationFieldReceivedLocation(v *M4Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM4ConfigurationMethodMarshalAPERBudget(v *M4Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM4ConfigurationMethodUnmarshalAPERFrom(v *M4Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeM5ConfigurationFieldPerPadding(v *M5Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM5ConfigurationFieldReceived(v *M5Configuration) *bool { return &v.received }
func BridgeM5ConfigurationFieldReceivedBytes(v *M5Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM5ConfigurationFieldReceivedLocation(v *M5Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM5ConfigurationMethodMarshalAPERBudget(v *M5Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM5ConfigurationMethodUnmarshalAPERFrom(v *M5Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeM6ConfigurationFieldPerPadding(v *M6Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM6ConfigurationFieldReceived(v *M6Configuration) *bool { return &v.received }
func BridgeM6ConfigurationFieldReceivedBytes(v *M6Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM6ConfigurationFieldReceivedLocation(v *M6Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM6ConfigurationMethodMarshalAPERBudget(v *M6Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM6ConfigurationMethodUnmarshalAPERFrom(v *M6Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeM7ConfigurationFieldPerPadding(v *M7Configuration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeM7ConfigurationFieldReceived(v *M7Configuration) *bool { return &v.received }
func BridgeM7ConfigurationFieldReceivedBytes(v *M7Configuration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeM7ConfigurationFieldReceivedLocation(v *M7Configuration) *aper.Location {
	return &v.receivedLocation
}
func BridgeM7ConfigurationMethodMarshalAPERBudget(v *M7Configuration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeM7ConfigurationMethodUnmarshalAPERFrom(v *M7Configuration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(v *MBSFNResultToLogInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMBSFNResultToLogInfoMethodUnmarshalAPERFrom(v *MBSFNResultToLogInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMDTModeExtensionMethodMarshalAPERTo(v *MDTModeExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTModeExtensionMethodUnmarshalAPERFrom(v *MDTModeExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMECPRelocationIndicationFieldPerPadding(v *MMECPRelocationIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v *MMECPRelocationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMECPRelocationIndicationMethodUnmarshalAPERFrom(v *MMECPRelocationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMeasurementThresholdA2MethodMarshalAPERBudget(v *MeasurementThresholdA2, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementThresholdL1LoggedMDTMethodMarshalAPERBudget(v *MeasurementThresholdL1LoggedMDT, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget(v *MultiCellLoadReportingResponseItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(v *MultiCellLoadReportingResponseItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERFrom(v *MultiCellLoadReportingResponseItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMutingPatternInformationFieldPerPadding(v *MutingPatternInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMutingPatternInformationFieldReceived(v *MutingPatternInformation) *bool {
	return &v.received
}
func BridgeMutingPatternInformationFieldReceivedBytes(v *MutingPatternInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMutingPatternInformationFieldReceivedLocation(v *MutingPatternInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeMutingPatternInformationMethodMarshalAPERBudget(v *MutingPatternInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMutingPatternInformationMethodUnmarshalAPERFrom(v *MutingPatternInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeNASDeliveryIndicationFieldPerPadding(v *NASDeliveryIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v *NASDeliveryIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNASDeliveryIndicationMethodUnmarshalAPERFrom(v *NASDeliveryIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldCodec(v *NASNonDeliveryIndicationCauseIEBinding) *s17.CauseValueCodec {
	return &v.codec
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldGet(v *NASNonDeliveryIndicationCauseIEBinding) *func(*NASNonDeliveryIndicationIEValue) (*s17.Cause, bool) {
	return &v.get
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldInfo(v *NASNonDeliveryIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeNASNonDeliveryIndicationCauseIEBindingFieldInject(v *NASNonDeliveryIndicationCauseIEBinding) *func(s17.Cause) NASNonDeliveryIndicationIEValue {
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
func BridgeNASNonDeliveryIndicationIEFieldFieldReplay(v *NASNonDeliveryIndicationIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeNASNonDeliveryIndicationIEValueFieldId(v *NASNonDeliveryIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeNASNonDeliveryIndicationIEValueFieldIsOpaque(v *NASNonDeliveryIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeNASNonDeliveryIndicationIEValueFieldOpaque(v *NASNonDeliveryIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeNASNonDeliveryIndicationIEValueFieldRowCause(v *NASNonDeliveryIndicationIEValue) **s17.Cause {
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
func BridgeNASNonDeliveryIndicationIEValueMethodEncodeFresh(v NASNonDeliveryIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeNASNonDeliveryIndicationIEValueMethodMatchesID(v NASNonDeliveryIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeNASNonDeliveryIndicationIEValueMethodRule(v NASNonDeliveryIndicationIEValue) aper.SourceRule {
	return v.rule()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *LocationReportingFailureIndicationIEValue) Selected() (any, bool) {
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
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *NASNonDeliveryIndicationIEValue) Selected() (any, bool) {
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
	case 26:
		if value, ok := v.AsNASPDU(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	}
	return nil, false
}
