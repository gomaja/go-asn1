// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s20 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s20

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
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// RerouteNASRequestIEContainer is ProtocolIE-Container {{RerouteNASRequest-IEs}} of TS 36.413: a list of RerouteNASRequestIEField values.
type RerouteNASRequestIEContainer []RerouteNASRequestIEField

// RerouteNASRequestIEField is ProtocolIE-Field {{RerouteNASRequest-IEs}} of TS 36.413: an information element field.
type RerouteNASRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         RerouteNASRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEField) WithoutReplay() RerouteNASRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *RerouteNASRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *RerouteNASRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *RerouteNASRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RerouteNASRequestIEField{}
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
	var zero RerouteNASRequestIEValue

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

// S1RemovalRequestIEContainer is ProtocolIE-Container {{S1RemovalRequestIEs}} of TS 36.413: a list of S1RemovalRequestIEField values.
type S1RemovalRequestIEContainer []S1RemovalRequestIEField

// S1RemovalRequestIEField is ProtocolIE-Field {{S1RemovalRequestIEs}} of TS 36.413: an information element field.
type S1RemovalRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         S1RemovalRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEField) WithoutReplay() S1RemovalRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *S1RemovalRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *S1RemovalRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *S1RemovalRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1RemovalRequestIEField{}
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
	var zero S1RemovalRequestIEValue

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

// RATRestrictionsValueCodec is the concrete ValueCodec[RATRestrictions].
type RATRestrictionsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RATRestrictions,

		error)
	encode func(RATRestrictions,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RATRestrictions, aper.DecodeState,

	) (RATRestrictions, aper.Snapshot,

	)
	compare func(RATRestrictions, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RATRestrictionsValueCodec) New(value RATRestrictions,

) (RATRestrictionsAPERValue, error) {
	if c.encode == nil {
		return RATRestrictionsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RATRestrictionsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RATRestrictionsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RATRestrictionsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RATRestrictionsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RATRestrictionsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RATRestrictionsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RATRestrictionsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RATRestrictionsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RATRestrictionsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RATRestrictionsValueCodec) EncodeAPER(value RATRestrictionsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RATRestrictionsValueCodec) encodeBudgetValue(value RATRestrictions,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RATRestrictionsValueCodec) encodeChanged(value RATRestrictions,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedPSCellListValueCodec is the concrete ValueCodec[LastVisitedPSCellList].
type LastVisitedPSCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedPSCellList,

		error)
	encode func(LastVisitedPSCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedPSCellList, aper.DecodeState,

	) (LastVisitedPSCellList, aper.Snapshot,

	)
	compare func(LastVisitedPSCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedPSCellListValueCodec) New(value LastVisitedPSCellList,

) (LastVisitedPSCellListAPERValue, error) {
	if c.encode == nil {
		return LastVisitedPSCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedPSCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedPSCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedPSCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedPSCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedPSCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedPSCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedPSCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedPSCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedPSCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedPSCellListValueCodec) EncodeAPER(value LastVisitedPSCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LastVisitedPSCellListValueCodec) encodeBudgetValue(value LastVisitedPSCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedPSCellListValueCodec) encodeChanged(value LastVisitedPSCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIESONInformationReportIEBinding binds SONInformationReport to the SONInformation-ExtensionIE object set of TS 36.413.
type SONInformationExtensionIESONInformationReportIEBinding struct {
	info   s00.FieldInfo
	codec  SONInformationReportValueCodec
	inject func(SONInformationReport,

	) SONInformationExtensionIEIEValue

	get func(*SONInformationExtensionIEIEValue,

	) (*SONInformationReport,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Codec() SONInformationReportValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONInformationExtensionIESONInformationReportIEBinding) New(value SONInformationReport,

) (SONInformationExtensionIEIEField, error) {
	if b.inject == nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	return SONInformationExtensionIEIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONInformationExtensionIESONInformationReportIEBinding) Get(field *SONInformationExtensionIEIEField) (*SONInformationReport,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SONInformationReportValueCodec is the concrete ValueCodec[SONInformationReport].
type SONInformationReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationReport,

		error)
	encode func(SONInformationReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationReport, aper.DecodeState,

	) (SONInformationReport, aper.Snapshot,

	)
	compare func(SONInformationReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationReportValueCodec) New(value SONInformationReport,

) (SONInformationReportAPERValue, error) {
	if c.encode == nil {
		return SONInformationReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationReportValueCodec) EncodeAPER(value SONInformationReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationReportValueCodec) encodeBudgetValue(value SONInformationReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationReportValueCodec) encodeChanged(value SONInformationReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEField is ProtocolIE-Field {{SONInformation-ExtensionIE}} of TS 36.413: an information element field.
type SONInformationExtensionIEIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SONInformationExtensionIEIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEField) WithoutReplay() SONInformationExtensionIEIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONInformationExtensionIEIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONInformationExtensionIEIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *SONInformationExtensionIEIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationExtensionIEIEField{}
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
	var zero SONInformationExtensionIEIEValue

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

// PSCellInformationValueCodec is the concrete ValueCodec[PSCellInformation].
type PSCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PSCellInformation,

		error)
	encode func(PSCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PSCellInformation, aper.DecodeState,

	) (PSCellInformation, aper.Snapshot,

	)
	compare func(PSCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PSCellInformationValueCodec) New(value PSCellInformation,

) (PSCellInformationAPERValue, error) {
	if c.encode == nil {
		return PSCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PSCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PSCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PSCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PSCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PSCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PSCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PSCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PSCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PSCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PSCellInformationValueCodec) EncodeAPER(value PSCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PSCellInformationValueCodec) encodeBudgetValue(value PSCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PSCellInformationValueCodec) encodeChanged(value PSCellInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeAuthorizedValueCodec is the concrete ValueCodec[ProSeAuthorized].
type ProSeAuthorizedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ProSeAuthorized,

		error)
	encode func(ProSeAuthorized,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ProSeAuthorized, aper.DecodeState,

	) (ProSeAuthorized, aper.Snapshot,

	)
	compare func(ProSeAuthorized, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeAuthorizedValueCodec) New(value ProSeAuthorized,

) (ProSeAuthorizedAPERValue, error) {
	if c.encode == nil {
		return ProSeAuthorizedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeAuthorizedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeAuthorizedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeAuthorizedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeAuthorizedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeAuthorizedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeAuthorizedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeAuthorizedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeAuthorizedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeAuthorizedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeAuthorizedValueCodec) EncodeAPER(value ProSeAuthorizedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ProSeAuthorizedValueCodec) encodeBudgetValue(value ProSeAuthorized,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeAuthorizedValueCodec) encodeChanged(value ProSeAuthorized,

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

// PWSfailedECGIListValueCodec is the concrete ValueCodec[PWSfailedECGIList].
type PWSfailedECGIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSfailedECGIList,

		error)
	encode func(PWSfailedECGIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSfailedECGIList, aper.DecodeState,

	) (PWSfailedECGIList, aper.Snapshot,

	)
	compare func(PWSfailedECGIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSfailedECGIListValueCodec) New(value PWSfailedECGIList,

) (PWSfailedECGIListAPERValue, error) {
	if c.encode == nil {
		return PWSfailedECGIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSfailedECGIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSfailedECGIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSfailedECGIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSfailedECGIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSfailedECGIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSfailedECGIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSfailedECGIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSfailedECGIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSfailedECGIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSfailedECGIListValueCodec) EncodeAPER(value PWSfailedECGIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PWSfailedECGIListValueCodec) encodeBudgetValue(value PWSfailedECGIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSfailedECGIListValueCodec) encodeChanged(value PWSfailedECGIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingEDRXInformationValueCodec is the concrete ValueCodec[PagingEDRXInformation].
type PagingEDRXInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingEDRXInformation,

		error)
	encode func(PagingEDRXInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingEDRXInformation, aper.DecodeState,

	) (PagingEDRXInformation, aper.Snapshot,

	)
	compare func(PagingEDRXInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingEDRXInformationValueCodec) New(value PagingEDRXInformation,

) (PagingEDRXInformationAPERValue, error) {
	if c.encode == nil {
		return PagingEDRXInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingEDRXInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingEDRXInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingEDRXInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingEDRXInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingEDRXInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingEDRXInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingEDRXInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingEDRXInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingEDRXInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingEDRXInformationValueCodec) EncodeAPER(value PagingEDRXInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingEDRXInformationValueCodec) encodeBudgetValue(value PagingEDRXInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingEDRXInformationValueCodec) encodeChanged(value PagingEDRXInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestENBUES1APIDIEBinding binds ENBUES1APID to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestENBUES1APIDIEBinding) Get(field *RerouteNASRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestMMEUES1APIDIEBinding binds MMEUES1APID to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestMMEUES1APIDIEBinding) Get(field *RerouteNASRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestSliceByteIEBinding binds []byte to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestSliceByteIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SliceByteValueCodec
	inject func([]byte,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*[]byte,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestSliceByteIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestSliceByteIEBinding) Codec() s01.SliceByteValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestSliceByteIEBinding) New(value []byte,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSliceByteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestSliceByteIEBinding) Get(field *RerouteNASRequestIEField) (*[]byte,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestMMEGroupIDIEBinding binds MMEGroupID to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestMMEGroupIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEGroupIDValueCodec
	inject func(s00.MMEGroupID,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*s00.MMEGroupID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Codec() s01.MMEGroupIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestMMEGroupIDIEBinding) New(value s00.MMEGroupID,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEGroupIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestMMEGroupIDIEBinding) Get(field *RerouteNASRequestIEField) (*s00.MMEGroupID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestAdditionalGUTIIEBinding binds AdditionalGUTI to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestAdditionalGUTIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.AdditionalGUTIValueCodec
	inject func(s18.AdditionalGUTI,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*s18.AdditionalGUTI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestAdditionalGUTIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestAdditionalGUTIIEBinding) Codec() s18.AdditionalGUTIValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestAdditionalGUTIIEBinding) New(value s18.AdditionalGUTI,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeAdditionalGUTIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestAdditionalGUTIIEBinding) Get(field *RerouteNASRequestIEField) (*s18.AdditionalGUTI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// RerouteNASRequestUEUsageTypeIEBinding binds UEUsageType to the RerouteNASRequest-IEs object set of TS 36.413.
type RerouteNASRequestUEUsageTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUsageTypeValueCodec
	inject func(s00.UEUsageType,

	) RerouteNASRequestIEValue

	get func(*RerouteNASRequestIEValue,

	) (*s00.UEUsageType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Codec() s02.UEUsageTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b RerouteNASRequestUEUsageTypeIEBinding) New(value s00.UEUsageType,

) (RerouteNASRequestIEField, error) {
	if b.inject == nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUsageTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return RerouteNASRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return RerouteNASRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b RerouteNASRequestUEUsageTypeIEBinding) Get(field *RerouteNASRequestIEField) (*s00.UEUsageType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// S1RemovalRequestGlobalENBIDIEBinding binds GlobalENBID to the S1RemovalRequestIEs object set of TS 36.413.
type S1RemovalRequestGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GlobalENBIDValueCodec
	inject func(s18.GlobalENBID,

	) S1RemovalRequestIEValue

	get func(*S1RemovalRequestIEValue,

	) (*s18.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Codec() s18.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b S1RemovalRequestGlobalENBIDIEBinding) New(value s18.GlobalENBID,

) (S1RemovalRequestIEField, error) {
	if b.inject == nil {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return S1RemovalRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return S1RemovalRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b S1RemovalRequestGlobalENBIDIEBinding) Get(field *S1RemovalRequestIEField) (*s18.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LastVisitedPSCellInformationValueCodec is the concrete ValueCodec[LastVisitedPSCellInformation].
type LastVisitedPSCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LastVisitedPSCellInformation,

		error)
	encode func(LastVisitedPSCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LastVisitedPSCellInformation, aper.DecodeState,

	) (LastVisitedPSCellInformation, aper.Snapshot,

	)
	compare func(LastVisitedPSCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedPSCellInformationValueCodec) New(value LastVisitedPSCellInformation,

) (LastVisitedPSCellInformationAPERValue, error) {
	if c.encode == nil {
		return LastVisitedPSCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedPSCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedPSCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedPSCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedPSCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedPSCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedPSCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedPSCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedPSCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedPSCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedPSCellInformationValueCodec) EncodeAPER(value LastVisitedPSCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LastVisitedPSCellInformationValueCodec) encodeBudgetValue(value LastVisitedPSCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedPSCellInformationValueCodec) encodeChanged(value LastVisitedPSCellInformation,

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

// PC5QoSFlowItemValueCodec is the concrete ValueCodec[PC5QoSFlowItem].
type PC5QoSFlowItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSFlowItem,

		error)
	encode func(PC5QoSFlowItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSFlowItem, aper.DecodeState,

	) (PC5QoSFlowItem, aper.Snapshot,

	)
	compare func(PC5QoSFlowItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSFlowItemValueCodec) New(value PC5QoSFlowItem,

) (PC5QoSFlowItemAPERValue, error) {
	if c.encode == nil {
		return PC5QoSFlowItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSFlowItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSFlowItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSFlowItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSFlowItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSFlowItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSFlowItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSFlowItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSFlowItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSFlowItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSFlowItemValueCodec) EncodeAPER(value PC5QoSFlowItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSFlowItemValueCodec) encodeBudgetValue(value PC5QoSFlowItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSFlowItemValueCodec) encodeChanged(value PC5QoSFlowItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSFlowListValueCodec is the concrete ValueCodec[PC5QoSFlowList].
type PC5QoSFlowListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSFlowList,

		error)
	encode func(PC5QoSFlowList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSFlowList, aper.DecodeState,

	) (PC5QoSFlowList, aper.Snapshot,

	)
	compare func(PC5QoSFlowList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSFlowListValueCodec) New(value PC5QoSFlowList,

) (PC5QoSFlowListAPERValue, error) {
	if c.encode == nil {
		return PC5QoSFlowListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSFlowListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSFlowListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSFlowListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSFlowListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSFlowListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSFlowListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSFlowListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSFlowListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSFlowListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSFlowListValueCodec) EncodeAPER(value PC5QoSFlowListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSFlowListValueCodec) encodeBudgetValue(value PC5QoSFlowList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSFlowListValueCodec) encodeChanged(value PC5QoSFlowList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PLMNAreaBasedQMCValueCodec is the concrete ValueCodec[PLMNAreaBasedQMC].
type PLMNAreaBasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PLMNAreaBasedQMC,

		error)
	encode func(PLMNAreaBasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PLMNAreaBasedQMC, aper.DecodeState,

	) (PLMNAreaBasedQMC, aper.Snapshot,

	)
	compare func(PLMNAreaBasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PLMNAreaBasedQMCValueCodec) New(value PLMNAreaBasedQMC,

) (PLMNAreaBasedQMCAPERValue, error) {
	if c.encode == nil {
		return PLMNAreaBasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNAreaBasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNAreaBasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PLMNAreaBasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PLMNAreaBasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNAreaBasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PLMNAreaBasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PLMNAreaBasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PLMNAreaBasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PLMNAreaBasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PLMNAreaBasedQMCValueCodec) EncodeAPER(value PLMNAreaBasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PLMNAreaBasedQMCValueCodec) encodeBudgetValue(value PLMNAreaBasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PLMNAreaBasedQMCValueCodec) encodeChanged(value PLMNAreaBasedQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingAttemptInformationValueCodec is the concrete ValueCodec[PagingAttemptInformation].
type PagingAttemptInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingAttemptInformation,

		error)
	encode func(PagingAttemptInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingAttemptInformation, aper.DecodeState,

	) (PagingAttemptInformation, aper.Snapshot,

	)
	compare func(PagingAttemptInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingAttemptInformationValueCodec) New(value PagingAttemptInformation,

) (PagingAttemptInformationAPERValue, error) {
	if c.encode == nil {
		return PagingAttemptInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAttemptInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAttemptInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAttemptInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingAttemptInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAttemptInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAttemptInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAttemptInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAttemptInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAttemptInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingAttemptInformationValueCodec) EncodeAPER(value PagingAttemptInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PagingAttemptInformationValueCodec) encodeBudgetValue(value PagingAttemptInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingAttemptInformationValueCodec) encodeChanged(value PagingAttemptInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PrivateIEIDValueCodec is the concrete ValueCodec[PrivateIEID].
type PrivateIEIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PrivateIEID,

		error)
	encode func(PrivateIEID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PrivateIEID, aper.DecodeState,

	) (PrivateIEID, aper.Snapshot,

	)
	compare func(PrivateIEID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PrivateIEIDValueCodec) New(value PrivateIEID,

) (PrivateIEIDAPERValue, error) {
	if c.encode == nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PrivateIEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PrivateIEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateIEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PrivateIEIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PrivateIEIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PrivateIEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PrivateIEIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PrivateIEIDValueCodec) EncodeAPER(value PrivateIEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PrivateIEIDValueCodec) encodeBudgetValue(value PrivateIEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PrivateIEIDValueCodec) encodeChanged(value PrivateIEID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RATRestrictionsItemValueCodec is the concrete ValueCodec[RATRestrictionsItem].
type RATRestrictionsItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RATRestrictionsItem,

		error)
	encode func(RATRestrictionsItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RATRestrictionsItem, aper.DecodeState,

	) (RATRestrictionsItem, aper.Snapshot,

	)
	compare func(RATRestrictionsItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RATRestrictionsItemValueCodec) New(value RATRestrictionsItem,

) (RATRestrictionsItemAPERValue, error) {
	if c.encode == nil {
		return RATRestrictionsItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RATRestrictionsItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RATRestrictionsItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RATRestrictionsItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RATRestrictionsItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RATRestrictionsItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RATRestrictionsItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RATRestrictionsItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RATRestrictionsItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RATRestrictionsItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RATRestrictionsItemValueCodec) EncodeAPER(value RATRestrictionsItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RATRestrictionsItemValueCodec) encodeBudgetValue(value RATRestrictionsItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RATRestrictionsItemValueCodec) encodeChanged(value RATRestrictionsItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RLFReportInformationValueCodec is the concrete ValueCodec[RLFReportInformation].
type RLFReportInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RLFReportInformation,

		error)
	encode func(RLFReportInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RLFReportInformation, aper.DecodeState,

	) (RLFReportInformation, aper.Snapshot,

	)
	compare func(RLFReportInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RLFReportInformationValueCodec) New(value RLFReportInformation,

) (RLFReportInformationAPERValue, error) {
	if c.encode == nil {
		return RLFReportInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RLFReportInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RLFReportInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RLFReportInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RLFReportInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RLFReportInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RLFReportInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RLFReportInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RLFReportInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RLFReportInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RLFReportInformationValueCodec) EncodeAPER(value RLFReportInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RLFReportInformationValueCodec) encodeBudgetValue(value RLFReportInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RLFReportInformationValueCodec) encodeChanged(value RLFReportInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReportingCellListValueCodec is the concrete ValueCodec[ReportingCellList].
type ReportingCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ReportingCellList,

		error)
	encode func(ReportingCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ReportingCellList, aper.DecodeState,

	) (ReportingCellList, aper.Snapshot,

	)
	compare func(ReportingCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReportingCellListValueCodec) New(value ReportingCellList,

) (ReportingCellListAPERValue, error) {
	if c.encode == nil {
		return ReportingCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportingCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportingCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReportingCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReportingCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportingCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReportingCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReportingCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReportingCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReportingCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReportingCellListValueCodec) EncodeAPER(value ReportingCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ReportingCellListValueCodec) encodeBudgetValue(value ReportingCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReportingCellListValueCodec) encodeChanged(value ReportingCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReportingCellListItemValueCodec is the concrete ValueCodec[ReportingCellListItem].
type ReportingCellListItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ReportingCellListItem,

		error)
	encode func(ReportingCellListItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ReportingCellListItem, aper.DecodeState,

	) (ReportingCellListItem, aper.Snapshot,

	)
	compare func(ReportingCellListItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReportingCellListItemValueCodec) New(value ReportingCellListItem,

) (ReportingCellListItemAPERValue, error) {
	if c.encode == nil {
		return ReportingCellListItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportingCellListItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportingCellListItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReportingCellListItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReportingCellListItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportingCellListItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReportingCellListItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReportingCellListItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReportingCellListItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReportingCellListItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReportingCellListItemValueCodec) EncodeAPER(value ReportingCellListItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ReportingCellListItemValueCodec) encodeBudgetValue(value ReportingCellListItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReportingCellListItemValueCodec) encodeChanged(value ReportingCellListItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RequestedCellListValueCodec is the concrete ValueCodec[RequestedCellList].
type RequestedCellListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RequestedCellList,

		error)
	encode func(RequestedCellList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RequestedCellList, aper.DecodeState,

	) (RequestedCellList, aper.Snapshot,

	)
	compare func(RequestedCellList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestedCellListValueCodec) New(value RequestedCellList,

) (RequestedCellListAPERValue, error) {
	if c.encode == nil {
		return RequestedCellListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestedCellListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedCellListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestedCellListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestedCellListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestedCellListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestedCellListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestedCellListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestedCellListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestedCellListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestedCellListValueCodec) EncodeAPER(value RequestedCellListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RequestedCellListValueCodec) encodeBudgetValue(value RequestedCellList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestedCellListValueCodec) encodeChanged(value RequestedCellList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionValueCodec is the concrete ValueCodec[SONInformationExtension].
type SONInformationExtensionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtension,

		error)
	encode func(SONInformationExtension,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtension, aper.DecodeState,

	) (SONInformationExtension, aper.Snapshot,

	)
	compare func(SONInformationExtension, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionValueCodec) New(value SONInformationExtension,

) (SONInformationExtensionAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionValueCodec) EncodeAPER(value SONInformationExtensionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionValueCodec) encodeBudgetValue(value SONInformationExtension,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionValueCodec) encodeChanged(value SONInformationExtension,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferCauseValueCodec is the concrete ValueCodec[SONtransferCause].
type SONtransferCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferCause,

		error)
	encode func(SONtransferCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferCause, aper.DecodeState,

	) (SONtransferCause, aper.Snapshot,

	)
	compare func(SONtransferCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferCauseValueCodec) New(value SONtransferCause,

) (SONtransferCauseAPERValue, error) {
	if c.encode == nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferCauseValueCodec) EncodeAPER(value SONtransferCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONtransferCauseValueCodec) encodeBudgetValue(value SONtransferCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferCauseValueCodec) encodeChanged(value SONtransferCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNodeIDExtensionValueCodec is the concrete ValueCodec[SourceNodeIDExtension].
type SourceNodeIDExtensionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceNodeIDExtension,

		error)
	encode func(SourceNodeIDExtension,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceNodeIDExtension, aper.DecodeState,

	) (SourceNodeIDExtension, aper.Snapshot,

	)
	compare func(SourceNodeIDExtension, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNodeIDExtensionValueCodec) New(value SourceNodeIDExtension,

) (SourceNodeIDExtensionAPERValue, error) {
	if c.encode == nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNodeIDExtensionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNodeIDExtensionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNodeIDExtensionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNodeIDExtensionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNodeIDExtensionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNodeIDExtensionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNodeIDExtensionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNodeIDExtensionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNodeIDExtensionValueCodec) EncodeAPER(value SourceNodeIDExtensionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SourceNodeIDExtensionValueCodec) encodeBudgetValue(value SourceNodeIDExtension,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNodeIDExtensionValueCodec) encodeChanged(value SourceNodeIDExtension,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RATRestrictionsAPERValue is the concrete APERValue[RATRestrictions].
type RATRestrictionsAPERValue struct {
	context s00.BridgeCodecContext
	Value   RATRestrictions

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RATRestrictionsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsAPERValue) WithoutReplay() RATRestrictionsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedPSCellListAPERValue is the concrete APERValue[LastVisitedPSCellList].
type LastVisitedPSCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   LastVisitedPSCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedPSCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellListAPERValue) WithoutReplay() LastVisitedPSCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationReportAPERValue is the concrete APERValue[SONInformationReport].
type SONInformationReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformationReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReportAPERValue) WithoutReplay() SONInformationReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PSCellInformationAPERValue is the concrete APERValue[PSCellInformation].
type PSCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PSCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PSCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSCellInformationAPERValue) WithoutReplay() PSCellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeAuthorizedAPERValue is the concrete APERValue[ProSeAuthorized].
type ProSeAuthorizedAPERValue struct {
	context s00.BridgeCodecContext
	Value   ProSeAuthorized

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeAuthorizedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeAuthorizedAPERValue) WithoutReplay() ProSeAuthorizedAPERValue {
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

// PWSfailedECGIListAPERValue is the concrete APERValue[PWSfailedECGIList].
type PWSfailedECGIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   PWSfailedECGIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSfailedECGIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSfailedECGIListAPERValue) WithoutReplay() PWSfailedECGIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingEDRXInformationAPERValue is the concrete APERValue[PagingEDRXInformation].
type PagingEDRXInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PagingEDRXInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingEDRXInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXInformationAPERValue) WithoutReplay() PagingEDRXInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedPSCellInformationAPERValue is the concrete APERValue[LastVisitedPSCellInformation].
type LastVisitedPSCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   LastVisitedPSCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedPSCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedPSCellInformationAPERValue) WithoutReplay() LastVisitedPSCellInformationAPERValue {
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

// PC5QoSFlowItemAPERValue is the concrete APERValue[PC5QoSFlowItem].
type PC5QoSFlowItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   PC5QoSFlowItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSFlowItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowItemAPERValue) WithoutReplay() PC5QoSFlowItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSFlowListAPERValue is the concrete APERValue[PC5QoSFlowList].
type PC5QoSFlowListAPERValue struct {
	context s00.BridgeCodecContext
	Value   PC5QoSFlowList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSFlowListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSFlowListAPERValue) WithoutReplay() PC5QoSFlowListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNAreaBasedQMCAPERValue is the concrete APERValue[PLMNAreaBasedQMC].
type PLMNAreaBasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   PLMNAreaBasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PLMNAreaBasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNAreaBasedQMCAPERValue) WithoutReplay() PLMNAreaBasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAttemptInformationAPERValue is the concrete APERValue[PagingAttemptInformation].
type PagingAttemptInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PagingAttemptInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAttemptInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptInformationAPERValue) WithoutReplay() PagingAttemptInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateIEIDAPERValue is the concrete APERValue[PrivateIEID].
type PrivateIEIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   PrivateIEID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PrivateIEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivateIEIDAPERValue) WithoutReplay() PrivateIEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RATRestrictionsItemAPERValue is the concrete APERValue[RATRestrictionsItem].
type RATRestrictionsItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   RATRestrictionsItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RATRestrictionsItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATRestrictionsItemAPERValue) WithoutReplay() RATRestrictionsItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RLFReportInformationAPERValue is the concrete APERValue[RLFReportInformation].
type RLFReportInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   RLFReportInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RLFReportInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RLFReportInformationAPERValue) WithoutReplay() RLFReportInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReportingCellListAPERValue is the concrete APERValue[ReportingCellList].
type ReportingCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ReportingCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReportingCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReportingCellListAPERValue) WithoutReplay() ReportingCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReportingCellListItemAPERValue is the concrete APERValue[ReportingCellListItem].
type ReportingCellListItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ReportingCellListItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReportingCellListItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReportingCellListItemAPERValue) WithoutReplay() ReportingCellListItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RequestedCellListAPERValue is the concrete APERValue[RequestedCellList].
type RequestedCellListAPERValue struct {
	context s00.BridgeCodecContext
	Value   RequestedCellList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestedCellListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestedCellListAPERValue) WithoutReplay() RequestedCellListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionAPERValue is the concrete APERValue[SONInformationExtension].
type SONInformationExtensionAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformationExtension

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionAPERValue) WithoutReplay() SONInformationExtensionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferCauseAPERValue is the concrete APERValue[SONtransferCause].
type SONtransferCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferCauseAPERValue) WithoutReplay() SONtransferCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNodeIDExtensionAPERValue is the concrete APERValue[SourceNodeIDExtension].
type SourceNodeIDExtensionAPERValue struct {
	context s00.BridgeCodecContext
	Value   SourceNodeIDExtension

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNodeIDExtensionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNodeIDExtensionAPERValue) WithoutReplay() SourceNodeIDExtensionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueERABIEContainerList].
type RerouteNASRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, error)
	encode  func(RerouteNASRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueERABIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) New(value RerouteNASRequestIEValueERABIEContainerList) (RerouteNASRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueERABIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{RerouteNASRequest-IEs}} of TS 36.413: a list of information element fields.
type RerouteNASRequestIEValueERABIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueERABIEContainerList].
type S1RemovalRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, error)
	encode  func(S1RemovalRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueERABIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) New(value S1RemovalRequestIEValueERABIEContainerList) (S1RemovalRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueERABIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{S1RemovalRequestIEs}} of TS 36.413: a list of information element fields.
type S1RemovalRequestIEValueERABIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueERABIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueERABIEContainerList].
type SONInformationExtensionIEIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueERABIEContainerList) (SONInformationExtensionIEIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueERABIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueERABIEContainerList is E-RAB-IE-ContainerList {{SONInformation-ExtensionIE}} of TS 36.413: a list of information element fields.
type SONInformationExtensionIEIEValueERABIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEContainer is ProtocolIE-Container {{SONInformation-ExtensionIE}} of TS 36.413: a list of SONInformationExtensionIEIEField values.
type SONInformationExtensionIEIEContainer []SONInformationExtensionIEIEField

// RerouteNASRequestIEFieldValueCodec is the concrete ValueCodec[RerouteNASRequestIEField].
type RerouteNASRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEField, error)
	encode  func(RerouteNASRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEField, aper.DecodeState) (RerouteNASRequestIEField, aper.Snapshot)
	compare func(RerouteNASRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEFieldValueCodec) New(value RerouteNASRequestIEField) (RerouteNASRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEFieldValueCodec) EncodeAPER(value RerouteNASRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEFieldValueCodec) encodeBudgetValue(value RerouteNASRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEFieldValueCodec) encodeChanged(value RerouteNASRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEFieldValueCodec is the concrete ValueCodec[S1RemovalRequestIEField].
type S1RemovalRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEField, error)
	encode  func(S1RemovalRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEField, aper.DecodeState) (S1RemovalRequestIEField, aper.Snapshot)
	compare func(S1RemovalRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEFieldValueCodec) New(value S1RemovalRequestIEField) (S1RemovalRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEFieldValueCodec) EncodeAPER(value S1RemovalRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEFieldValueCodec) encodeBudgetValue(value S1RemovalRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEFieldValueCodec) encodeChanged(value S1RemovalRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEFieldValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEField].
type SONInformationExtensionIEIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEField, error)
	encode  func(SONInformationExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEField, aper.DecodeState) (SONInformationExtensionIEIEField, aper.Snapshot)
	compare func(SONInformationExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEFieldValueCodec) New(value SONInformationExtensionIEIEField) (SONInformationExtensionIEIEFieldAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEFieldValueCodec) EncodeAPER(value SONInformationExtensionIEIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEFieldValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEFieldValueCodec) encodeChanged(value SONInformationExtensionIEIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEContainerValueCodec is the concrete ValueCodec[RerouteNASRequestIEContainer].
type RerouteNASRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEContainer, error)
	encode  func(RerouteNASRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEContainer, aper.DecodeState) (RerouteNASRequestIEContainer, aper.Snapshot)
	compare func(RerouteNASRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEContainerValueCodec) New(value RerouteNASRequestIEContainer) (RerouteNASRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEContainerValueCodec) EncodeAPER(value RerouteNASRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEContainerValueCodec) encodeBudgetValue(value RerouteNASRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEContainerValueCodec) encodeChanged(value RerouteNASRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEContainerValueCodec is the concrete ValueCodec[S1RemovalRequestIEContainer].
type S1RemovalRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEContainer, error)
	encode  func(S1RemovalRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEContainer, aper.DecodeState) (S1RemovalRequestIEContainer, aper.Snapshot)
	compare func(S1RemovalRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEContainerValueCodec) New(value S1RemovalRequestIEContainer) (S1RemovalRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEContainerValueCodec) EncodeAPER(value S1RemovalRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEContainerValueCodec) encodeBudgetValue(value S1RemovalRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEContainerValueCodec) encodeChanged(value S1RemovalRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEContainerValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEContainer].
type SONInformationExtensionIEIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEContainer, error)
	encode  func(SONInformationExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEContainer, aper.DecodeState) (SONInformationExtensionIEIEContainer, aper.Snapshot)
	compare func(SONInformationExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEContainerValueCodec) New(value SONInformationExtensionIEIEContainer) (SONInformationExtensionIEIEContainerAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEContainerValueCodec) EncodeAPER(value SONInformationExtensionIEIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEContainerValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEContainerValueCodec) encodeChanged(value SONInformationExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueProtocolErrorIEContainerList].
type RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(RerouteNASRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) New(value RerouteNASRequestIEValueProtocolErrorIEContainerList) (RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{RerouteNASRequest-IEs}} of TS 36.413: a list of information element fields.
type RerouteNASRequestIEValueProtocolErrorIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueProtocolErrorIEContainerList].
type S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(S1RemovalRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) New(value S1RemovalRequestIEValueProtocolErrorIEContainerList) (S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{S1RemovalRequestIEs}} of TS 36.413: a list of information element fields.
type S1RemovalRequestIEValueProtocolErrorIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueProtocolErrorIEContainerList].
type SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList) (SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{SONInformation-ExtensionIE}} of TS 36.413: a list of information element fields.
type SONInformationExtensionIEIEValueProtocolErrorIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// RerouteNASRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[RerouteNASRequestIEValueProtocolIEContainerList].
type RerouteNASRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, error)
	encode  func(RerouteNASRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RerouteNASRequestIEValueProtocolIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) New(value RerouteNASRequestIEValueProtocolIEContainerList) (RerouteNASRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RerouteNASRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RerouteNASRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value RerouteNASRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value RerouteNASRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RerouteNASRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value RerouteNASRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RerouteNASRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {RerouteNASRequest-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type RerouteNASRequestIEValueProtocolIEContainerList []RerouteNASRequestIEValueProtocolIESingleContainer

// S1RemovalRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[S1RemovalRequestIEValueProtocolIEContainerList].
type S1RemovalRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, error)
	encode  func(S1RemovalRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1RemovalRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) New(value S1RemovalRequestIEValueProtocolIEContainerList) (S1RemovalRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1RemovalRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1RemovalRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value S1RemovalRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value S1RemovalRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1RemovalRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value S1RemovalRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1RemovalRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {S1RemovalRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type S1RemovalRequestIEValueProtocolIEContainerList []S1RemovalRequestIEValueProtocolIESingleContainer

// SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[SONInformationExtensionIEIEValueProtocolIEContainerList].
type SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, error)
	encode  func(SONInformationExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) New(value SONInformationExtensionIEIEValueProtocolIEContainerList) (SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) EncodeAPER(value SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value SONInformationExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) encodeChanged(value SONInformationExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationExtensionIEIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {SONInformation-ExtensionIE} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type SONInformationExtensionIEIEValueProtocolIEContainerList []SONInformationExtensionIEIEValueProtocolIESingleContainer

// RerouteNASRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueERABIEContainerList].
type RerouteNASRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueERABIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{RerouteNASRequest-IEs}} of TS 36.413: a single information element field.
type RerouteNASRequestIEValueProtocolIESingleContainer = RerouteNASRequestIEField

// S1RemovalRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueERABIEContainerList].
type S1RemovalRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueERABIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{S1RemovalRequestIEs}} of TS 36.413: a single information element field.
type S1RemovalRequestIEValueProtocolIESingleContainer = S1RemovalRequestIEField

// SONInformationExtensionIEIEValueERABIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueERABIEContainerList].
type SONInformationExtensionIEIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueERABIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{SONInformation-ExtensionIE}} of TS 36.413: a single information element field.
type SONInformationExtensionIEIEValueProtocolIESingleContainer = SONInformationExtensionIEIEField

// RerouteNASRequestIEFieldAPERValue is the concrete APERValue[RerouteNASRequestIEField].
type RerouteNASRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEFieldAPERValue) WithoutReplay() RerouteNASRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEFieldAPERValue is the concrete APERValue[S1RemovalRequestIEField].
type S1RemovalRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEFieldAPERValue) WithoutReplay() S1RemovalRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEFieldAPERValue is the concrete APERValue[SONInformationExtensionIEIEField].
type SONInformationExtensionIEIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEFieldAPERValue) WithoutReplay() SONInformationExtensionIEIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEContainerAPERValue is the concrete APERValue[RerouteNASRequestIEContainer].
type RerouteNASRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEContainerAPERValue) WithoutReplay() RerouteNASRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEContainerAPERValue is the concrete APERValue[S1RemovalRequestIEContainer].
type S1RemovalRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEContainerAPERValue) WithoutReplay() S1RemovalRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEContainerAPERValue is the concrete APERValue[SONInformationExtensionIEIEContainer].
type SONInformationExtensionIEIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEContainerAPERValue) WithoutReplay() SONInformationExtensionIEIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueProtocolErrorIEContainerList].
type RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueProtocolErrorIEContainerList].
type S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueProtocolErrorIEContainerList].
type SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RerouteNASRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[RerouteNASRequestIEValueProtocolIEContainerList].
type RerouteNASRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         RerouteNASRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RerouteNASRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RerouteNASRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() RerouteNASRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1RemovalRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[S1RemovalRequestIEValueProtocolIEContainerList].
type S1RemovalRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         S1RemovalRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1RemovalRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1RemovalRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() S1RemovalRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue is the concrete APERValue[SONInformationExtensionIEIEValueProtocolIEContainerList].
type SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationExtensionIEIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) WithoutReplay() SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APLastVisitedPSCellInformation(v *LastVisitedPSCellInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.PSCellID == nil)
		if v.PSCellID != nil {
			BridgeCaptureS1APPSCellInformation(v.PSCellID, s)
		}
		s.End(f, nil, false)
	}
	s.Int(int64(v.TimeStay))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLastVisitedPSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedPSCellInformation(v *LastVisitedPSCellInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.PSCellID == nil)
		if v.PSCellID != nil {
			BridgeCompareS1APPSCellInformation(v.PSCellID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Int(int64(v.TimeStay))
	s.Bool(v.IEExtensions == nil)
	s13.BridgeLastVisitedPSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgeNRV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgeNRV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgePC5FlowBitRatesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s14.BridgePC5FlowBitRatesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPC5QoSFlowItem(v *PC5QoSFlowItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APFiveQI(&v.PQI, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5FlowBitRates == nil)
		if v.Pc5FlowBitRates != nil {
			BridgeCaptureS1APPC5FlowBitRates(v.Pc5FlowBitRates, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.Range == nil)
		if v.Range != nil {
			s00.BridgeCaptureS1APRange(v.Range, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePC5QoSFlowItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPC5QoSFlowItem(v *PC5QoSFlowItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APFiveQI(&v.PQI, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5FlowBitRates == nil)
		if v.Pc5FlowBitRates != nil {
			BridgeCompareS1APPC5FlowBitRates(v.Pc5FlowBitRates, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.Range == nil)
		if v.Range != nil {
			s06.BridgeCompareS1APRange(v.Range, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePC5QoSFlowItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPLMNAreaBasedQMC(v *PLMNAreaBasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNListforQMC(&v.PlmnListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s14.BridgePLMNAreaBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPLMNAreaBasedQMC(v *PLMNAreaBasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNListforQMC(&v.PlmnListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s14.BridgePLMNAreaBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPSCellInformation(v *PSCellInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCaptureS1APNRCGI(&v.NCGI, s)
	s.Bool(v.IEExtensions == nil)
	s14.BridgePSCellInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPSCellInformation(v *PSCellInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCompareS1APNRCGI(&v.NCGI, s)
	s.Bool(v.IEExtensions == nil)
	s14.BridgePSCellInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPagingAttemptInformation(v *PagingAttemptInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPagingAttemptCount(&v.PagingAttemptCount, s)
	s00.BridgeCaptureS1APIntendedNumberOfPagingAttempts(&v.IntendedNumberOfPagingAttempts, s)
	{
		f := s.Begin()
		s.Bool(v.NextPagingAreaScope == nil)
		if v.NextPagingAreaScope != nil {
			s00.BridgeCaptureS1APNextPagingAreaScope(v.NextPagingAreaScope, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePagingAttemptInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPagingAttemptInformation(v *PagingAttemptInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPagingAttemptCount(&v.PagingAttemptCount, s)
	s02.BridgeCompareS1APIntendedNumberOfPagingAttempts(&v.IntendedNumberOfPagingAttempts, s)
	{
		f := s.Begin()
		s.Bool(v.NextPagingAreaScope == nil)
		if v.NextPagingAreaScope != nil {
			s02.BridgeCompareS1APNextPagingAreaScope(v.NextPagingAreaScope, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePagingAttemptInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPagingEDRXInformation(v *PagingEDRXInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPagingEDRXCycle(&v.PagingEDRXCycle, s)
	{
		f := s.Begin()
		s.Bool(v.PagingTimeWindow == nil)
		if v.PagingTimeWindow != nil {
			s00.BridgeCaptureS1APPagingTimeWindow(v.PagingTimeWindow, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePagingEDRXInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPagingEDRXInformation(v *PagingEDRXInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPagingEDRXCycle(&v.PagingEDRXCycle, s)
	{
		f := s.Begin()
		s.Bool(v.PagingTimeWindow == nil)
		if v.PagingTimeWindow != nil {
			s02.BridgeCompareS1APPagingTimeWindow(v.PagingTimeWindow, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgePagingEDRXInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPrivateIEID(v *PrivateIEID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, nil, false)
		}
	case s00.PrivateIEIDChoiceGlobal:
		{
			f := s.Begin()
			s.Bool(v.Global == nil)
			if v.Global != nil {
				s.String((*v.Global).Encoded())
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPrivateIEID(v *PrivateIEID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PrivateIEIDChoiceGlobal:
		{
			f := s.Begin()
			s.Bool(v.Global == nil)
			if v.Global != nil {
				s.String((*v.Global).Encoded())
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APProSeAuthorized(v *ProSeAuthorized, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ProSeDirectDiscovery == nil)
		if v.ProSeDirectDiscovery != nil {
			s00.BridgeCaptureS1APProSeDirectDiscovery(v.ProSeDirectDiscovery, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProSeDirectCommunication == nil)
		if v.ProSeDirectCommunication != nil {
			s00.BridgeCaptureS1APProSeDirectCommunication(v.ProSeDirectCommunication, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeProSeAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APProSeAuthorized(v *ProSeAuthorized, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.ProSeDirectDiscovery == nil)
		if v.ProSeDirectDiscovery != nil {
			s02.BridgeCompareS1APProSeDirectDiscovery(v.ProSeDirectDiscovery, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ProSeDirectCommunication == nil)
		if v.ProSeDirectCommunication != nil {
			s02.BridgeCompareS1APProSeDirectCommunication(v.ProSeDirectCommunication, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeProSeAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRATRestrictionsItem(v *RATRestrictionsItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.PLMNidentity, s)
	s.BitString(v.RATRestrictionInformation.Bytes, v.RATRestrictionInformation.BitLength)
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRATRestrictionsItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRATRestrictionsItem(v *RATRestrictionsItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.PLMNidentity, s)
	s.BitString(v.RATRestrictionInformation.Bytes, v.RATRestrictionInformation.BitLength)
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRATRestrictionsItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRLFReportInformation(v *RLFReportInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APUERLFReportContainer(&v.UERLFReportContainer, s)
	{
		f := s.Begin()
		s.Bool(v.UERLFReportContainerForExtendedBands == nil)
		if v.UERLFReportContainerForExtendedBands != nil {
			s00.BridgeCaptureS1APUERLFReportContainerForExtendedBands(v.UERLFReportContainerForExtendedBands, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRLFReportInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRLFReportInformation(v *RLFReportInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APUERLFReportContainer(&v.UERLFReportContainer, s)
	{
		f := s.Begin()
		s.Bool(v.UERLFReportContainerForExtendedBands == nil)
		if v.UERLFReportContainerForExtendedBands != nil {
			s07.BridgeCompareS1APUERLFReportContainerForExtendedBands(v.UERLFReportContainerForExtendedBands, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRLFReportInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APReportingCellListItem(v *ReportingCellListItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APIRATCellID(&v.CellID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APReportingCellListItem(v *ReportingCellListItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APIRATCellID(&v.CellID, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRerouteNASRequestIEValue(v *RerouteNASRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(225):
			{
				f := s.Begin()
				s.Bool(v.rowS1Message == nil)
				if v.rowS1Message != nil {
					s.Bytes((*v.rowS1Message))
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(223):
			{
				f := s.Begin()
				s.Bool(v.rowMMEGroupID == nil)
				if v.rowMMEGroupID != nil {
					s00.BridgeCaptureS1APMMEGroupID(v.rowMMEGroupID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(224):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalGUTI == nil)
				if v.rowAdditionalGUTI != nil {
					s18.BridgeCaptureS1APAdditionalGUTI(v.rowAdditionalGUTI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(230):
			{
				f := s.Begin()
				s.Bool(v.rowUEUsageType == nil)
				if v.rowUEUsageType != nil {
					s00.BridgeCaptureS1APUEUsageType(v.rowUEUsageType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RerouteNASRequestIEValue) captureSemantics(s aper.SemanticCapture) RerouteNASRequestIEValue {
	BridgeCaptureS1APRerouteNASRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APRerouteNASRequestIEValue(v *RerouteNASRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(225):
			{
				f := s.Begin()
				s.Bool(v.rowS1Message == nil)
				if v.rowS1Message != nil {
					s.Bytes((*v.rowS1Message))
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(223):
			{
				f := s.Begin()
				s.Bool(v.rowMMEGroupID == nil)
				if v.rowMMEGroupID != nil {
					s02.BridgeCompareS1APMMEGroupID(v.rowMMEGroupID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(224):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalGUTI == nil)
				if v.rowAdditionalGUTI != nil {
					s18.BridgeCompareS1APAdditionalGUTI(v.rowAdditionalGUTI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(230):
			{
				f := s.Begin()
				s.Bool(v.rowUEUsageType == nil)
				if v.rowUEUsageType != nil {
					s07.BridgeCompareS1APUEUsageType(v.rowUEUsageType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v RerouteNASRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APRerouteNASRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1RemovalRequestIEValue(v *S1RemovalRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalRequestIEValue) captureSemantics(s aper.SemanticCapture) S1RemovalRequestIEValue {
	BridgeCaptureS1APS1RemovalRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APS1RemovalRequestIEValue(v *S1RemovalRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v S1RemovalRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APS1RemovalRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONInformationExtension(v *SONInformationExtension, s *aper.SemanticCapture) {
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
func BridgeCompareS1APSONInformationExtension(v *SONInformationExtension, s *aper.SemanticComparison) {
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
func BridgeCaptureS1APSONInformationExtensionIEIEValue(v *SONInformationExtensionIEIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(206):
			{
				f := s.Begin()
				s.Bool(v.rowSONInformationReport == nil)
				if v.rowSONInformationReport != nil {
					BridgeCaptureS1APSONInformationReport(v.rowSONInformationReport, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationExtensionIEIEValue) captureSemantics(s aper.SemanticCapture) SONInformationExtensionIEIEValue {
	BridgeCaptureS1APSONInformationExtensionIEIEValue(&v, &s)
	return v
}
func BridgeCompareS1APSONInformationExtensionIEIEValue(v *SONInformationExtensionIEIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(206):
			{
				f := s.Begin()
				s.Bool(v.rowSONInformationReport == nil)
				if v.rowSONInformationReport != nil {
					BridgeCompareS1APSONInformationReport(v.rowSONInformationReport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationExtensionIEIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSONInformationExtensionIEIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONInformationReport(v *SONInformationReport, s *aper.SemanticCapture) {
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
	case s00.SONInformationReportChoiceRLFReportInformation:
		{
			f := s.Begin()
			s.Bool(v.RLFReportInformation == nil)
			if v.RLFReportInformation != nil {
				BridgeCaptureS1APRLFReportInformation(v.RLFReportInformation, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSONInformationReport(v *SONInformationReport, s *aper.SemanticComparison) {
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
	case s00.SONInformationReportChoiceRLFReportInformation:
		{
			f := s.Begin()
			s.Bool(v.RLFReportInformation == nil)
			if v.RLFReportInformation != nil {
				BridgeCompareS1APRLFReportInformation(v.RLFReportInformation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSONtransferCause(v *SONtransferCause, s *aper.SemanticCapture) {
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
	case s00.SONtransferCauseChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.CellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.MultiCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s00.BridgeCaptureS1APCellLoadReportingCause(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s00.BridgeCaptureS1APHOReportingCause(v.HOReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s00.BridgeCaptureS1APCellActivationCause(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				s00.BridgeCaptureS1APCellStateIndicationCause(v.EnergySavingsIndication, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferCauseChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s00.BridgeCaptureS1APFailureEventReportingCause(v.FailureEventReporting, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferCause(v *SONtransferCause, s *aper.SemanticComparison) {
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
	case s00.SONtransferCauseChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.CellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.MultiCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s02.BridgeCompareS1APCellLoadReportingCause(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s02.BridgeCompareS1APHOReportingCause(v.HOReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s02.BridgeCompareS1APCellActivationCause(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				s02.BridgeCompareS1APCellStateIndicationCause(v.EnergySavingsIndication, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferCauseChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s02.BridgeCompareS1APFailureEventReportingCause(v.FailureEventReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APSourceNodeIDExtension(v *SourceNodeIDExtension, s *aper.SemanticCapture) {
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
func BridgeCompareS1APSourceNodeIDExtension(v *SourceNodeIDExtension, s *aper.SemanticComparison) {
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

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding      `json:"-"`
	perOpenTypePadding aper.CompletePadding      `json:"-"`
	Local              *int64                    `json:"Local,omitempty"`
	Global             *runtime.ObjectIdentifier `json:"Global,omitempty"`
}

// MarshalAPER encodes PrivateIEID to APER format.
func (v *PrivateIEID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *PrivateIEID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) &&
		!v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "PrivateIEID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		if v.Local == nil {
			return fmt.Errorf("choice alternative local is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.Local), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
			return fmt.Errorf("encoding local: %w", err)
		}
	case s00.PrivateIEIDChoiceGlobal:
		if v.Global == nil {
			return fmt.Errorf("choice alternative global is nil")
		}
		if err := aper.EncodeObjectIdentifierAligned(bb, *v.Global); err != nil {
			return fmt.Errorf("encoding global: %w", err)
		}
	default:
		return fmt.Errorf("unknown PrivateIEID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PrivateIEID from APER format.
func (v *PrivateIEID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateIEID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateIEID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	bb.EnterComponent("PrivateIEID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	padding, err := aper.CaptureFinalBits(bb, "PrivateIEID")
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *PrivateIEID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEID{}
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
	case s00.PrivateIEIDChoiceLocal:
		val_local, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Local")
		}
		if err := aper.ChargeValue(bb, val_local); err != nil {
			return err
		}
		v.Local = (*int64)(bb.OwnInt64(int64(val_local)))

	case s00.PrivateIEIDChoiceGlobal:
		val_global, err := aper.DecodeObjectIdentifierAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "Global")
		}
		tmp_global := val_global
		if err := aper.ChargeValue(bb, tmp_global); err != nil {
			return err
		}
		v.Global = &tmp_global
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PrivateIEID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateIEID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PrivateIEID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateIEID) WithoutReplay() PrivateIEID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PrivateIEID
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PrivateIEID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PrivateIEID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PrivateIEID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PrivateIEID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPrivateIEID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PrivateIEID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PrivateIEID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PrivateIEID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PrivateIEID")
}
func (v *PrivateIEID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PrivateIEID")
}
func (v *PrivateIEID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPrivateIEID(v, &s)
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
func (v *PrivateIEID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PrivateIEID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PrivateIEID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PrivateIEID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PrivateIEID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPrivateIEID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PrivateIEID{}
		return report, aper.OperationError(err, "PrivateIEID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PrivateIEID")
}

type PWSfailedECGIList = []s17.EUTRANCGI
type LastVisitedPSCellList = []LastVisitedPSCellInformation

// LastVisitedPSCellInformation represents the ASN.1 type LastVisitedPSCellInformation (SEQUENCE).
type LastVisitedPSCellInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PSCellID          *PSCellInformation                                 `asn1:"tag:0,context,implicit,optional" json:"PSCellID,omitempty"`
	TimeStay          int64                                              `asn1:"tag:1,context,implicit"`
	IEExtensions      s09.LastVisitedPSCellInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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

// PagingAttemptInformation represents the ASN.1 type PagingAttemptInformation (SEQUENCE).
type PagingAttemptInformation struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	received                       bool
	withoutReplay                  bool
	receivedAbsolute               bool
	receivedBytes                  aper.WireSpan
	receivedLocation               aper.Location
	PagingAttemptCount             s00.PagingAttemptCount                         `asn1:"tag:0,context,implicit"`
	IntendedNumberOfPagingAttempts s00.IntendedNumberOfPagingAttempts             `asn1:"tag:1,context,implicit"`
	NextPagingAreaScope            *s00.NextPagingAreaScope                       `asn1:"tag:2,context,implicit,optional" json:"NextPagingAreaScope,omitempty"`
	IEExtensions                   s10.PagingAttemptInformationExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                           `asn1:"-" json:"-"`
	extCount                       int64                                          `asn1:"-" json:"-"`
	extPresent                     []bool                                         `asn1:"-" json:"-"`
	extData                        [][]byte                                       `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}

// PagingEDRXInformation represents the ASN.1 type Paging-eDRXInformation (SEQUENCE).
type PagingEDRXInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PagingEDRXCycle   s00.PagingEDRXCycle                         `asn1:"tag:0,context,implicit"`
	PagingTimeWindow  *s00.PagingTimeWindow                       `asn1:"tag:1,context,implicit,optional" json:"PagingTimeWindow,omitempty"`
	IEExtensions      s10.PagingEDRXInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type PC5QoSFlowList = []PC5QoSFlowItem

// PC5QoSFlowItem represents the ASN.1 type PC5QoSFlowItem (SEQUENCE).
type PC5QoSFlowItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	PQI               s00.FiveQI                           `asn1:"tag:0,context,implicit"`
	Pc5FlowBitRates   *PC5FlowBitRates                     `asn1:"tag:1,context,implicit,optional" json:"Pc5FlowBitRates,omitempty"`
	Range             *s00.Range                           `asn1:"tag:2,context,implicit,optional" json:"Range,omitempty"`
	IEExtensions      s10.PC5QoSFlowItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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

// PLMNAreaBasedQMC represents the ASN.1 type PLMNAreaBasedQMC (SEQUENCE).
type PLMNAreaBasedQMC struct {
	replay              aper.Snapshot
	stream              aper.WireSpan
	received            bool
	withoutReplay       bool
	receivedAbsolute    bool
	receivedBytes       aper.WireSpan
	receivedLocation    aper.Location
	PlmnListforQMC      s00.PLMNListforQMC                     `asn1:"tag:0,context,implicit"`
	plmnListforQMCIndef bool                                   `asn1:"-" json:"-"`
	IEExtensions        s10.PLMNAreaBasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef   bool                                   `asn1:"-" json:"-"`
	extCount            int64                                  `asn1:"-" json:"-"`
	extPresent          []bool                                 `asn1:"-" json:"-"`
	extData             [][]byte                               `asn1:"-" json:"-"`
	perPadding          aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding       []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin           []aper.OpaqueOrigin
	extWire             []aper.WireSpan
}

// ProSeAuthorized represents the ASN.1 type ProSeAuthorized (SEQUENCE).
type ProSeAuthorized struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	received                 bool
	withoutReplay            bool
	receivedAbsolute         bool
	receivedBytes            aper.WireSpan
	receivedLocation         aper.Location
	ProSeDirectDiscovery     *s00.ProSeDirectDiscovery             `asn1:"tag:0,context,implicit,optional" json:"ProSeDirectDiscovery,omitempty"`
	ProSeDirectCommunication *s00.ProSeDirectCommunication         `asn1:"tag:1,context,implicit,optional" json:"ProSeDirectCommunication,omitempty"`
	IEExtensions             s10.ProSeAuthorizedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                  `asn1:"-" json:"-"`
	extCount                 int64                                 `asn1:"-" json:"-"`
	extPresent               []bool                                `asn1:"-" json:"-"`
	extData                  [][]byte                              `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// PSCellInformation represents the ASN.1 type PSCellInformation (SEQUENCE).
type PSCellInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	NCGI              s19.NRCGI                               `asn1:"tag:0,context,implicit"`
	IEExtensions      s10.PSCellInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                    `asn1:"-" json:"-"`
	extCount          int64                                   `asn1:"-" json:"-"`
	extPresent        []bool                                  `asn1:"-" json:"-"`
	extData           [][]byte                                `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type RATRestrictions = []RATRestrictionsItem

// RATRestrictionsItem represents the ASN.1 type RAT-RestrictionsItem (SEQUENCE).
type RATRestrictionsItem struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	PLMNidentity              s00.PLMNidentity                          `asn1:"tag:0,context,implicit"`
	RATRestrictionInformation runtime.BitString                         `asn1:"tag:1,context,implicit"`
	IEExtensions              s10.RATRestrictionsItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                      `asn1:"-" json:"-"`
	extCount                  int64                                     `asn1:"-" json:"-"`
	extPresent                []bool                                    `asn1:"-" json:"-"`
	extData                   [][]byte                                  `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// RLFReportInformation represents the ASN.1 type RLFReportInformation (SEQUENCE).
type RLFReportInformation struct {
	replay                               aper.Snapshot
	stream                               aper.WireSpan
	received                             bool
	withoutReplay                        bool
	receivedAbsolute                     bool
	receivedBytes                        aper.WireSpan
	receivedLocation                     aper.Location
	UERLFReportContainer                 s00.UERLFReportContainer                   `asn1:"tag:0,context,implicit"`
	UERLFReportContainerForExtendedBands *s00.UERLFReportContainerForExtendedBands  `asn1:"tag:1,context,implicit,optional" json:"UERLFReportContainerForExtendedBands,omitempty"`
	IEExtensions                         s10.RLFReportInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                    bool                                       `asn1:"-" json:"-"`
	extCount                             int64                                      `asn1:"-" json:"-"`
	extPresent                           []bool                                     `asn1:"-" json:"-"`
	extData                              [][]byte                                   `asn1:"-" json:"-"`
	perPadding                           aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding                        []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin                            []aper.OpaqueOrigin
	extWire                              []aper.WireSpan
}

// SONInformationExtension represents the ASN.1 type SONInformation-Extension (SEQUENCE).
type SONInformationExtension struct {
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

// SONInformationReport represents the ASN.1 CHOICE type SONInformationReport.
type SONInformationReport struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	Choice               int
	perPadding           aper.CompletePadding  `json:"-"`
	perOpenTypePadding   aper.CompletePadding  `json:"-"`
	UnknownExtension     *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	RLFReportInformation *RLFReportInformation `json:"RLFReportInformation,omitempty"`
}

// SourceNodeIDExtension represents the ASN.1 type SourceNodeID-Extension (SEQUENCE).
type SourceNodeIDExtension struct {
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

// MarshalAPER encodes LastVisitedPSCellInformation to APER format.
func (v *LastVisitedPSCellInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LastVisitedPSCellInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.PSCellID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.PSCellID != nil {
		if err := v.PSCellID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding pSCellID: %w", err)
		}
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.TimeStay), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(40950), false); err != nil {
		return fmt.Errorf("encoding timeStay: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LastVisitedPSCellInformation from APER format.
func (v *LastVisitedPSCellInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LastVisitedPSCellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LastVisitedPSCellInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellInformation")
	}
	bb.EnterComponent("LastVisitedPSCellInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "LastVisitedPSCellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "LastVisitedPSCellInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LastVisitedPSCellInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LastVisitedPSCellInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_pscellid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_pscellid {
		toleranceMark_pscellid := bb.EnterComponent("PSCellID")
		var dec_pscellid PSCellInformation
		if err := dec_pscellid.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "PSCellID")
		}
		if err := aper.ChargeValue(bb, dec_pscellid); err != nil {
			return err
		}
		v.PSCellID = &dec_pscellid
		bb.LeaveComponent(toleranceMark_pscellid)
	}
	val_timestay, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(40950), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeStay")
	}
	v.TimeStay = val_timestay
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.LastVisitedPSCellInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.LastVisitedPSCellInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeLastVisitedPSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("NRV2XServicesAuthorized")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.NRV2XServicesAuthorizedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRV2XServicesAuthorizedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeNRV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("NRUESidelinkAggregateMaximumBitrate")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.NRUESidelinkAggregateMaximumBitrateExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("OverloadResponse")
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

// MarshalAPER encodes PagingAttemptInformation to APER format.
func (v *PagingAttemptInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PagingAttemptInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.NextPagingAreaScope != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PagingAttemptCount, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
		return fmt.Errorf("encoding pagingAttemptCount: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.IntendedNumberOfPagingAttempts, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
		return fmt.Errorf("encoding intendedNumberOfPagingAttempts: %w", err)
	}
	if v.NextPagingAreaScope != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.NextPagingAreaScope), 2, true); err != nil {
			return fmt.Errorf("encoding nextPagingAreaScope: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PagingAttemptInformation from APER format.
func (v *PagingAttemptInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PagingAttemptInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PagingAttemptInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PagingAttemptInformation")
	}
	bb.EnterComponent("PagingAttemptInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PagingAttemptInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "PagingAttemptInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingAttemptInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PagingAttemptInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingAttemptInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nextpagingareascope, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pagingattemptcount, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingAttemptCount")
	}
	v.PagingAttemptCount = val_pagingattemptcount
	val_intendednumberofpagingattempts, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "IntendedNumberOfPagingAttempts")
	}
	v.IntendedNumberOfPagingAttempts = val_intendednumberofpagingattempts
	if opt_nextpagingareascope {
		val_nextpagingareascope, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NextPagingAreaScope"})
		if err != nil {
			return runtime.WrapDecodePath(err, "NextPagingAreaScope")
		}
		tmp_nextpagingareascope := s00.NextPagingAreaScope(val_nextpagingareascope)
		if err := aper.ChargeValue(bb, tmp_nextpagingareascope); err != nil {
			return err
		}
		v.NextPagingAreaScope = (*s00.NextPagingAreaScope)(bb.OwnInt64(int64(tmp_nextpagingareascope)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PagingAttemptInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PagingAttemptInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePagingAttemptInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PagingEDRXInformation to APER format.
func (v *PagingEDRXInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PagingEDRXInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.PagingTimeWindow != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PagingEDRXCycle), 14, true); err != nil {
		return fmt.Errorf("encoding paging-eDRX-Cycle: %w", err)
	}
	if v.PagingTimeWindow != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.PagingTimeWindow), 16, true); err != nil {
			return fmt.Errorf("encoding pagingTimeWindow: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PagingEDRXInformation from APER format.
func (v *PagingEDRXInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PagingEDRXInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PagingEDRXInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PagingEDRXInformation")
	}
	bb.EnterComponent("PagingEDRXInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PagingEDRXInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "PagingEDRXInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingEDRXInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PagingEDRXInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingEDRXInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_pagingtimewindow, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pagingedrxcycle, err := aper.DecodeEnumeratedAligned(bb, 14, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingEDRXCycle"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingEDRXCycle")
	}
	v.PagingEDRXCycle = s00.PagingEDRXCycle(val_pagingedrxcycle)
	if opt_pagingtimewindow {
		val_pagingtimewindow, err := aper.DecodeEnumeratedAligned(bb, 16, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingTimeWindow"})
		if err != nil {
			return runtime.WrapDecodePath(err, "PagingTimeWindow")
		}
		tmp_pagingtimewindow := s00.PagingTimeWindow(val_pagingtimewindow)
		if err := aper.ChargeValue(bb, tmp_pagingtimewindow); err != nil {
			return err
		}
		v.PagingTimeWindow = (*s00.PagingTimeWindow)(bb.OwnInt64(int64(tmp_pagingtimewindow)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PagingEDRXInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PagingEDRXInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePagingEDRXInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PC5QoSFlowItem to APER format.
func (v *PC5QoSFlowItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PC5QoSFlowItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.Pc5FlowBitRates != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.Range != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PQI, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound7, true); err != nil {
		return fmt.Errorf("encoding pQI: %w", err)
	}
	if v.Pc5FlowBitRates != nil {
		if err := v.Pc5FlowBitRates.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding pc5FlowBitRates: %w", err)
		}
	}
	if v.Range != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.Range), 9, true); err != nil {
			return fmt.Errorf("encoding range: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PC5QoSFlowItem from APER format.
func (v *PC5QoSFlowItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PC5QoSFlowItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PC5QoSFlowItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowItem")
	}
	bb.EnterComponent("PC5QoSFlowItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "PC5QoSFlowItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PC5QoSFlowItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSFlowItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_pc5flowbitrates, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_range, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pqi, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound7, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PQI")
	}
	v.PQI = val_pqi
	if opt_pc5flowbitrates {
		toleranceMark_pc5flowbitrates := bb.EnterComponent("Pc5FlowBitRates")
		var dec_pc5flowbitrates PC5FlowBitRates
		if err := dec_pc5flowbitrates.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "Pc5FlowBitRates")
		}
		if err := aper.ChargeValue(bb, dec_pc5flowbitrates); err != nil {
			return err
		}
		v.Pc5FlowBitRates = &dec_pc5flowbitrates
		bb.LeaveComponent(toleranceMark_pc5flowbitrates)
	}
	if opt_range {
		val_range, err := aper.DecodeEnumeratedAligned(bb, 9, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Range"})
		if err != nil {
			return runtime.WrapDecodePath(err, "Range")
		}
		tmp_range := s00.Range(val_range)
		if err := aper.ChargeValue(bb, tmp_range); err != nil {
			return err
		}
		v.Range = (*s00.Range)(bb.OwnInt64(int64(tmp_range)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PC5QoSFlowItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PC5QoSFlowItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePC5QoSFlowItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("PC5FlowBitRates")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PC5FlowBitRatesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PC5FlowBitRatesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePC5FlowBitRatesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PLMNAreaBasedQMC to APER format.
func (v *PLMNAreaBasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PLMNAreaBasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.PlmnListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_plmnlistforqmc, fragmentLength_plmnlistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_plmnlistforqmc < 0 || fragmentOffset_plmnlistforqmc > int64(len(v.PlmnListforQMC)) || fragmentLength_plmnlistforqmc < 0 || fragmentLength_plmnlistforqmc > int64(len(v.PlmnListforQMC[fragmentOffset_plmnlistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PlmnListforQMC[fragmentOffset_plmnlistforqmc : fragmentOffset_plmnlistforqmc+fragmentLength_plmnlistforqmc] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
				return fmt.Errorf("encoding plmnListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding plmnListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PLMNAreaBasedQMC from APER format.
func (v *PLMNAreaBasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PLMNAreaBasedQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PLMNAreaBasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PLMNAreaBasedQMC")
	}
	bb.EnterComponent("PLMNAreaBasedQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PLMNAreaBasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "PLMNAreaBasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNAreaBasedQMC")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PLMNAreaBasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PLMNAreaBasedQMC{}
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
	toleranceMark_plmnlistforqmc := bb.EnterComponent("PlmnListforQMC")
	v.PlmnListforQMC = make(s00.PLMNListforQMC, 0)
	_, errCollection_plmnlistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_plmnlistforqmc, fragmentLength_plmnlistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_plmnlistforqmc < 0 || fragmentLength_plmnlistforqmc < 0 || fragmentLength_plmnlistforqmc > int64(^uint(0)>>1) || fragmentOffset_plmnlistforqmc > int64(^uint(0)>>1)-fragmentLength_plmnlistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_plmnlistforqmc; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PlmnListforQMC[%d]", fragmentOffset_plmnlistforqmc+i))
			}
			if next, err := aper.AppendValues(bb, v.PlmnListforQMC, val); err != nil {
				return err
			} else {
				v.PlmnListforQMC = next
			}
		}
		return nil
	})
	if errCollection_plmnlistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_plmnlistforqmc, "PlmnListforQMC")
	}
	bb.LeaveComponent(toleranceMark_plmnlistforqmc)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PLMNAreaBasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PLMNAreaBasedQMCExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePLMNAreaBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ProSeAuthorized to APER format.
func (v *ProSeAuthorized) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ProSeAuthorized) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ProSeDirectDiscovery != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ProSeDirectCommunication != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.ProSeDirectDiscovery != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.ProSeDirectDiscovery), 2, true); err != nil {
			return fmt.Errorf("encoding proSeDirectDiscovery: %w", err)
		}
	}
	if v.ProSeDirectCommunication != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.ProSeDirectCommunication), 2, true); err != nil {
			return fmt.Errorf("encoding proSeDirectCommunication: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ProSeAuthorized from APER format.
func (v *ProSeAuthorized) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ProSeAuthorized with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ProSeAuthorized) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ProSeAuthorized")
	}
	bb.EnterComponent("ProSeAuthorized")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProSeAuthorized")
	}
	padding, err := aper.CaptureFinalBits(bb, "ProSeAuthorized")
	if err != nil {
		return runtime.WrapDecodePath(err, "ProSeAuthorized")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ProSeAuthorized) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProSeAuthorized{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_prosedirectdiscovery, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_prosedirectcommunication, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_prosedirectdiscovery {
		val_prosedirectdiscovery, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ProSeDirectDiscovery"})
		if err != nil {
			return runtime.WrapDecodePath(err, "ProSeDirectDiscovery")
		}
		tmp_prosedirectdiscovery := s00.ProSeDirectDiscovery(val_prosedirectdiscovery)
		if err := aper.ChargeValue(bb, tmp_prosedirectdiscovery); err != nil {
			return err
		}
		v.ProSeDirectDiscovery = (*s00.ProSeDirectDiscovery)(bb.OwnInt64(int64(tmp_prosedirectdiscovery)))

	}
	if opt_prosedirectcommunication {
		val_prosedirectcommunication, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ProSeDirectCommunication"})
		if err != nil {
			return runtime.WrapDecodePath(err, "ProSeDirectCommunication")
		}
		tmp_prosedirectcommunication := s00.ProSeDirectCommunication(val_prosedirectcommunication)
		if err := aper.ChargeValue(bb, tmp_prosedirectcommunication); err != nil {
			return err
		}
		v.ProSeDirectCommunication = (*s00.ProSeDirectCommunication)(bb.OwnInt64(int64(tmp_prosedirectcommunication)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.ProSeAuthorizedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.ProSeAuthorizedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeProSeAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PSCellInformation to APER format.
func (v *PSCellInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PSCellInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s19.BridgeNRCGIMethodMarshalAPERTo(&v.NCGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding nCGI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgePSCellInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PSCellInformation from APER format.
func (v *PSCellInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PSCellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PSCellInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PSCellInformation")
	}
	bb.EnterComponent("PSCellInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PSCellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "PSCellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "PSCellInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PSCellInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PSCellInformation{}
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
	toleranceMark_ncgi := bb.EnterComponent("NCGI")
	if err := s19.BridgeNRCGIMethodUnmarshalAPERFrom(&v.NCGI, bb); err != nil {
		return runtime.WrapDecodePath(err, "NCGI")
	}
	bb.LeaveComponent(toleranceMark_ncgi)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.PSCellInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.PSCellInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgePSCellInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RATRestrictionsItem to APER format.
func (v *RATRestrictionsItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RATRestrictionsItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.RATRestrictionInformation.Bytes, v.RATRestrictionInformation.BitLength, 8, 8, true, true); err != nil {
		return fmt.Errorf("encoding rAT-RestrictionInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RATRestrictionsItem from APER format.
func (v *RATRestrictionsItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RATRestrictionsItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RATRestrictionsItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictionsItem")
	}
	bb.EnterComponent("RATRestrictionsItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictionsItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "RATRestrictionsItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictionsItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RATRestrictionsItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RATRestrictionsItem{}
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
	bsBytes_ratrestrictioninformation, bsBitLen_ratrestrictioninformation, err := aper.DecodeBitStringAlignedExt(bb, 8, 8, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictionInformation")
	}
	v.RATRestrictionInformation = runtime.BitString{Bytes: bsBytes_ratrestrictioninformation, BitLength: bsBitLen_ratrestrictioninformation}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.RATRestrictionsItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.RATRestrictionsItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeRATRestrictionsItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RLFReportInformation to APER format.
func (v *RLFReportInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RLFReportInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.UERLFReportContainerForExtendedBands != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.UERLFReportContainer), 0, 0, false); err != nil {
		return fmt.Errorf("encoding uE-RLF-Report-Container: %w", err)
	}
	if v.UERLFReportContainerForExtendedBands != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.UERLFReportContainerForExtendedBands), 0, 0, false); err != nil {
			return fmt.Errorf("encoding uE-RLF-Report-Container-for-extended-bands: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RLFReportInformation from APER format.
func (v *RLFReportInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RLFReportInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RLFReportInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RLFReportInformation")
	}
	bb.EnterComponent("RLFReportInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RLFReportInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "RLFReportInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "RLFReportInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RLFReportInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RLFReportInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_uerlfreportcontainerforextendedbands, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uerlfreportcontainer, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UERLFReportContainer")
	}
	v.UERLFReportContainer = s00.UERLFReportContainer(val_uerlfreportcontainer)
	if opt_uerlfreportcontainerforextendedbands {
		val_uerlfreportcontainerforextendedbands, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
		if err != nil {
			return runtime.WrapDecodePath(err, "UERLFReportContainerForExtendedBands")
		}
		tmp_uerlfreportcontainerforextendedbands := s00.UERLFReportContainerForExtendedBands(val_uerlfreportcontainerforextendedbands)
		if err := aper.ChargeValue(bb, tmp_uerlfreportcontainerforextendedbands); err != nil {
			return err
		}
		v.UERLFReportContainerForExtendedBands = &tmp_uerlfreportcontainerforextendedbands
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.RLFReportInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.RLFReportInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeRLFReportInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SONInformationExtension to APER format.
func (v *SONInformationExtension) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONInformationExtension) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes SONInformationExtension from APER format.
func (v *SONInformationExtension) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONInformationExtension with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONInformationExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	bb.EnterComponent("SONInformationExtension")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformationExtension")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformationExtension")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONInformationExtension) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationExtension{}
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

// MarshalAPER encodes SONInformationReport to APER format.
func (v *SONInformationReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONInformationReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONInformationReport:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONInformationReport:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONInformationReport:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "SONInformationReport:", v.Choice)
	}
	switch v.Choice {
	case s00.SONInformationReportChoiceRLFReportInformation:
		if v.RLFReportInformation == nil {
			return fmt.Errorf("choice alternative rLFReportInformation is nil")
		}
		if err := v.RLFReportInformation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding rLFReportInformation: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONInformationReport choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONInformationReport from APER format.
func (v *SONInformationReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONInformationReport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONInformationReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	bb.EnterComponent("SONInformationReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformationReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReport")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONInformationReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReport{}
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
	case s00.SONInformationReportChoiceRLFReportInformation:
		toleranceMark_rlfreportinformation := bb.EnterComponent("RLFReportInformation")
		var dec_rlfreportinformation RLFReportInformation
		if err := dec_rlfreportinformation.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RLFReportInformation")
		}
		if err := aper.ChargeValue(bb, dec_rlfreportinformation); err != nil {
			return err
		}
		v.RLFReportInformation = &dec_rlfreportinformation
		bb.LeaveComponent(toleranceMark_rlfreportinformation)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SourceNodeIDExtension to APER format.
func (v *SourceNodeIDExtension) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SourceNodeIDExtension) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes SourceNodeIDExtension from APER format.
func (v *SourceNodeIDExtension) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SourceNodeIDExtension with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SourceNodeIDExtension) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	bb.EnterComponent("SourceNodeIDExtension")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	padding, err := aper.CaptureFinalBits(bb, "SourceNodeIDExtension")
	if err != nil {
		return runtime.WrapDecodePath(err, "SourceNodeIDExtension")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SourceNodeIDExtension) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceNodeIDExtension{}
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LastVisitedPSCellInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LastVisitedPSCellInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LastVisitedPSCellInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LastVisitedPSCellInformation) WithoutReplay() LastVisitedPSCellInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LastVisitedPSCellInformation
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PC5QoSFlowItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PC5QoSFlowItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PC5QoSFlowItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PC5QoSFlowItem) WithoutReplay() PC5QoSFlowItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PC5QoSFlowItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PLMNAreaBasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PLMNAreaBasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PLMNAreaBasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PLMNAreaBasedQMC) WithoutReplay() PLMNAreaBasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PLMNAreaBasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PSCellInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PSCellInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PSCellInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PSCellInformation) WithoutReplay() PSCellInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PSCellInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PagingAttemptInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PagingAttemptInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PagingAttemptInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PagingAttemptInformation) WithoutReplay() PagingAttemptInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PagingAttemptInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PagingEDRXInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PagingEDRXInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PagingEDRXInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PagingEDRXInformation) WithoutReplay() PagingEDRXInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PagingEDRXInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ProSeAuthorized) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ProSeAuthorized", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ProSeAuthorized", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ProSeAuthorized) WithoutReplay() ProSeAuthorized {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ProSeAuthorized
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RATRestrictionsItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RATRestrictionsItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RATRestrictionsItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RATRestrictionsItem) WithoutReplay() RATRestrictionsItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RATRestrictionsItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RLFReportInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RLFReportInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RLFReportInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RLFReportInformation) WithoutReplay() RLFReportInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RLFReportInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformationExtension) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationExtension", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformationExtension", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformationExtension) WithoutReplay() SONInformationExtension {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformationExtension
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformationReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformationReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformationReport) WithoutReplay() SONInformationReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformationReport
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SourceNodeIDExtension) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SourceNodeIDExtension", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SourceNodeIDExtension", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SourceNodeIDExtension) WithoutReplay() SourceNodeIDExtension {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SourceNodeIDExtension
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *LastVisitedPSCellInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LastVisitedPSCellInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LastVisitedPSCellInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LastVisitedPSCellInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LastVisitedPSCellInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LastVisitedPSCellInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LastVisitedPSCellInformation.Extensions[%d]", index))
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

// Extensions returns owned unknown sequence additions.
func (v *PC5QoSFlowItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PC5QoSFlowItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSFlowItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSFlowItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PC5QoSFlowItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSFlowItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSFlowItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PLMNAreaBasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PLMNAreaBasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PLMNAreaBasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PLMNAreaBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PLMNAreaBasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PLMNAreaBasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PLMNAreaBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PSCellInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PSCellInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PSCellInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PSCellInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PSCellInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PSCellInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PSCellInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PagingAttemptInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PagingAttemptInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PagingAttemptInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PagingAttemptInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PagingAttemptInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PagingAttemptInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PagingAttemptInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PagingEDRXInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PagingEDRXInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PagingEDRXInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PagingEDRXInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PagingEDRXInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PagingEDRXInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PagingEDRXInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ProSeAuthorized) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ProSeAuthorized) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ProSeAuthorized.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ProSeAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ProSeAuthorized) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ProSeAuthorized.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ProSeAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RATRestrictionsItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RATRestrictionsItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RATRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RATRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RATRestrictionsItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RATRestrictionsItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RATRestrictionsItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RLFReportInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RLFReportInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RLFReportInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RLFReportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RLFReportInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RLFReportInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RLFReportInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *LastVisitedPSCellInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LastVisitedPSCellInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LastVisitedPSCellInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LastVisitedPSCellInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLastVisitedPSCellInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LastVisitedPSCellInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LastVisitedPSCellInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LastVisitedPSCellInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LastVisitedPSCellInformation")
}
func (v *LastVisitedPSCellInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LastVisitedPSCellInformation")
}
func (v *LastVisitedPSCellInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLastVisitedPSCellInformation(v, &s)
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
func (v *LastVisitedPSCellInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LastVisitedPSCellInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PC5QoSFlowItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PC5QoSFlowItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PC5QoSFlowItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PC5QoSFlowItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPC5QoSFlowItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PC5QoSFlowItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PC5QoSFlowItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PC5QoSFlowItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PC5QoSFlowItem")
}
func (v *PC5QoSFlowItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PC5QoSFlowItem")
}
func (v *PC5QoSFlowItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPC5QoSFlowItem(v, &s)
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
func (v *PC5QoSFlowItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PC5QoSFlowItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PLMNAreaBasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PLMNAreaBasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PLMNAreaBasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PLMNAreaBasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPLMNAreaBasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PLMNAreaBasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PLMNAreaBasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PLMNAreaBasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PLMNAreaBasedQMC")
}
func (v *PLMNAreaBasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PLMNAreaBasedQMC")
}
func (v *PLMNAreaBasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPLMNAreaBasedQMC(v, &s)
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
func (v *PLMNAreaBasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PLMNAreaBasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PSCellInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PSCellInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PSCellInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PSCellInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPSCellInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PSCellInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PSCellInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PSCellInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PSCellInformation")
}
func (v *PSCellInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PSCellInformation")
}
func (v *PSCellInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPSCellInformation(v, &s)
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
func (v *PSCellInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PSCellInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PagingAttemptInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PagingAttemptInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PagingAttemptInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PagingAttemptInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPagingAttemptInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PagingAttemptInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PagingAttemptInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PagingAttemptInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PagingAttemptInformation")
}
func (v *PagingAttemptInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PagingAttemptInformation")
}
func (v *PagingAttemptInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPagingAttemptInformation(v, &s)
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
func (v *PagingAttemptInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PagingAttemptInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PagingEDRXInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PagingEDRXInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PagingEDRXInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PagingEDRXInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPagingEDRXInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PagingEDRXInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PagingEDRXInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PagingEDRXInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PagingEDRXInformation")
}
func (v *PagingEDRXInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PagingEDRXInformation")
}
func (v *PagingEDRXInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPagingEDRXInformation(v, &s)
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
func (v *PagingEDRXInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PagingEDRXInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ProSeAuthorized) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ProSeAuthorized")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ProSeAuthorized) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ProSeAuthorized")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APProSeAuthorized(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ProSeAuthorized")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ProSeAuthorized")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ProSeAuthorized) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ProSeAuthorized")
}
func (v *ProSeAuthorized) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ProSeAuthorized")
}
func (v *ProSeAuthorized) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APProSeAuthorized(v, &s)
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
func (v *ProSeAuthorized) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ProSeAuthorized) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RATRestrictionsItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RATRestrictionsItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RATRestrictionsItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RATRestrictionsItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRATRestrictionsItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RATRestrictionsItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RATRestrictionsItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RATRestrictionsItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RATRestrictionsItem")
}
func (v *RATRestrictionsItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RATRestrictionsItem")
}
func (v *RATRestrictionsItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRATRestrictionsItem(v, &s)
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
func (v *RATRestrictionsItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RATRestrictionsItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RLFReportInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RLFReportInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RLFReportInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RLFReportInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRLFReportInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RLFReportInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RLFReportInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RLFReportInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RLFReportInformation")
}
func (v *RLFReportInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RLFReportInformation")
}
func (v *RLFReportInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRLFReportInformation(v, &s)
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
func (v *RLFReportInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RLFReportInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONInformationExtension) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformationExtension")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformationExtension) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformationExtension")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformationExtension(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformationExtension")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformationExtension")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformationExtension) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformationExtension")
}
func (v *SONInformationExtension) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformationExtension")
}
func (v *SONInformationExtension) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformationExtension(v, &s)
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
func (v *SONInformationExtension) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformationExtension) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONInformationReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformationReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformationReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformationReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformationReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformationReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformationReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformationReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformationReport")
}
func (v *SONInformationReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformationReport")
}
func (v *SONInformationReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformationReport(v, &s)
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
func (v *SONInformationReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformationReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SourceNodeIDExtension) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SourceNodeIDExtension")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SourceNodeIDExtension) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SourceNodeIDExtension")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSourceNodeIDExtension(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SourceNodeIDExtension")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SourceNodeIDExtension")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SourceNodeIDExtension) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SourceNodeIDExtension")
}
func (v *SourceNodeIDExtension) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SourceNodeIDExtension")
}
func (v *SourceNodeIDExtension) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSourceNodeIDExtension(v, &s)
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
func (v *SourceNodeIDExtension) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SourceNodeIDExtension) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LastVisitedPSCellInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LastVisitedPSCellInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LastVisitedPSCellInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLastVisitedPSCellInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LastVisitedPSCellInformation{}
		return report, aper.OperationError(err, "LastVisitedPSCellInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LastVisitedPSCellInformation")
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PC5QoSFlowItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PC5QoSFlowItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PC5QoSFlowItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPC5QoSFlowItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PC5QoSFlowItem{}
		return report, aper.OperationError(err, "PC5QoSFlowItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PC5QoSFlowItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PLMNAreaBasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PLMNAreaBasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PLMNAreaBasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPLMNAreaBasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PLMNAreaBasedQMC{}
		return report, aper.OperationError(err, "PLMNAreaBasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PLMNAreaBasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PSCellInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PSCellInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PSCellInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPSCellInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PSCellInformation{}
		return report, aper.OperationError(err, "PSCellInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PSCellInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PagingAttemptInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PagingAttemptInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PagingAttemptInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPagingAttemptInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PagingAttemptInformation{}
		return report, aper.OperationError(err, "PagingAttemptInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PagingAttemptInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PagingEDRXInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PagingEDRXInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PagingEDRXInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPagingEDRXInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PagingEDRXInformation{}
		return report, aper.OperationError(err, "PagingEDRXInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PagingEDRXInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ProSeAuthorized) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ProSeAuthorized")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ProSeAuthorized
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APProSeAuthorized(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ProSeAuthorized{}
		return report, aper.OperationError(err, "ProSeAuthorized")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ProSeAuthorized")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RATRestrictionsItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RATRestrictionsItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RATRestrictionsItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRATRestrictionsItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RATRestrictionsItem{}
		return report, aper.OperationError(err, "RATRestrictionsItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RATRestrictionsItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RLFReportInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RLFReportInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RLFReportInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRLFReportInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RLFReportInformation{}
		return report, aper.OperationError(err, "RLFReportInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RLFReportInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformationExtension) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformationExtension")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformationExtension
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformationExtension(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformationExtension{}
		return report, aper.OperationError(err, "SONInformationExtension")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformationExtension")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformationReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformationReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformationReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformationReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformationReport{}
		return report, aper.OperationError(err, "SONInformationReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformationReport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SourceNodeIDExtension) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SourceNodeIDExtension")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SourceNodeIDExtension
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSourceNodeIDExtension(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SourceNodeIDExtension{}
		return report, aper.OperationError(err, "SourceNodeIDExtension")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SourceNodeIDExtension")
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
func NewDLCOUNTPDCPSNlengthUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s15.DLCOUNTPDCPSNlength, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
	}
	value := s15.DLCOUNTPDCPSNlength{UnknownExtension: &extension}
	if _, err := s15.BridgeDLCOUNTPDCPSNlengthMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s15.DLCOUNTPDCPSNlength{}, aper.OperationError(err, "DLCOUNTPDCPSNlengthUnknownExtension")
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
func NewGlobalRANNODEIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s19.GlobalRANNODEID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
	}
	value := s19.GlobalRANNODEID{UnknownExtension: &extension}
	if _, err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s19.GlobalRANNODEID{}, aper.OperationError(err, "GlobalRANNODEIDUnknownExtension")
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
func NewLoggedMDTTriggerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s19.LoggedMDTTrigger, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	value := s19.LoggedMDTTrigger{UnknownExtension: &extension}
	if _, err := s19.BridgeLoggedMDTTriggerMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s19.LoggedMDTTrigger{}, aper.OperationError(err, "LoggedMDTTriggerUnknownExtension")
	}
	return value, aper.OperationError(nil, "LoggedMDTTriggerUnknownExtension")
}

// NewMeasurementThresholdA2UnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMeasurementThresholdA2UnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s19.MeasurementThresholdA2, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
	}
	value := s19.MeasurementThresholdA2{UnknownExtension: &extension}
	if _, err := s19.BridgeMeasurementThresholdA2MethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s19.MeasurementThresholdA2{}, aper.OperationError(err, "MeasurementThresholdA2UnknownExtension")
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

// NewSONInformationReportUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONInformationReportUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONInformationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	value := SONInformationReport{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONInformationReport{}, aper.OperationError(err, "SONInformationReportUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONInformationReportUnknownExtension")
}

// SONtransferCause represents the ASN.1 CHOICE type SONtransferCause.
type SONtransferCause struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding            `json:"-"`
	perOpenTypePadding              aper.CompletePadding            `json:"-"`
	UnknownExtension                *aper.ChoiceExtension           `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *s00.CellLoadReportingCause     `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *s00.CellLoadReportingCause     `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *s00.CellLoadReportingCause     `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *s00.HOReportingCause           `json:"HOReporting,omitempty"`
	EutranCellActivation            *s00.CellActivationCause        `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *s00.CellStateIndicationCause   `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *s00.FailureEventReportingCause `json:"FailureEventReporting,omitempty"`
}
type RequestedCellList = []s18.IRATCellID

// ReportingCellListItem represents the ASN.1 type ReportingCellList-Item (SEQUENCE).
type ReportingCellListItem struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	CellID           s18.IRATCellID         `asn1:"tag:0,context,explicit"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type ReportingCellList = []ReportingCellListItem
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

// MarshalAPER encodes SONtransferCause to APER format.
func (v *SONtransferCause) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferCause) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferCause:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferCause:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferCause:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONtransferCause:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.SONtransferCauseChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.MultiCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EventTriggeredCellLoadReporting), 3, true); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.HOReporting), 3, true); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case s00.SONtransferCauseChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EutranCellActivation), 3, true); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferCauseChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.EnergySavingsIndication), 3, true); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case s00.SONtransferCauseChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := aper.EncodeEnumeratedAligned(inner, int64(*v.FailureEventReporting), 3, true); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferCause extension choice %d", v.Choice)
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
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CellLoadReporting), 3, true); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferCause choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferCause from APER format.
func (v *SONtransferCause) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONtransferCause with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONtransferCause) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	bb.EnterComponent("SONtransferCause")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferCause")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferCause")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferCause) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferCause{}
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
		if extIdx >= 6 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.SONtransferCauseChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			val_multicellloadreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MultiCellLoadReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			tmp_multicellloadreporting := s00.CellLoadReportingCause(val_multicellloadreporting)
			if err := aper.ChargeValue(inner, tmp_multicellloadreporting); err != nil {
				return err
			}
			v.MultiCellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_multicellloadreporting)))

		case s00.SONtransferCauseChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			val_eventtriggeredcellloadreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EventTriggeredCellLoadReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			tmp_eventtriggeredcellloadreporting := s00.CellLoadReportingCause(val_eventtriggeredcellloadreporting)
			if err := aper.ChargeValue(inner, tmp_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_eventtriggeredcellloadreporting)))

		case s00.SONtransferCauseChoiceHOReporting:
			extensionPath = "HOReporting"
			val_horeporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "HOReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			tmp_horeporting := s00.HOReportingCause(val_horeporting)
			if err := aper.ChargeValue(inner, tmp_horeporting); err != nil {
				return err
			}
			v.HOReporting = (*s00.HOReportingCause)(bb.OwnInt64(int64(tmp_horeporting)))

		case s00.SONtransferCauseChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			val_eutrancellactivation, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EutranCellActivation"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			tmp_eutrancellactivation := s00.CellActivationCause(val_eutrancellactivation)
			if err := aper.ChargeValue(inner, tmp_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = (*s00.CellActivationCause)(bb.OwnInt64(int64(tmp_eutrancellactivation)))

		case s00.SONtransferCauseChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			val_energysavingsindication, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnergySavingsIndication"})
			if err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			tmp_energysavingsindication := s00.CellStateIndicationCause(val_energysavingsindication)
			if err := aper.ChargeValue(inner, tmp_energysavingsindication); err != nil {
				return err
			}
			v.EnergySavingsIndication = (*s00.CellStateIndicationCause)(bb.OwnInt64(int64(tmp_energysavingsindication)))

		case s00.SONtransferCauseChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			val_failureeventreporting, err := aper.DecodeEnumeratedAligned(inner, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "FailureEventReporting"})
			if err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			tmp_failureeventreporting := s00.FailureEventReportingCause(val_failureeventreporting)
			if err := aper.ChargeValue(inner, tmp_failureeventreporting); err != nil {
				return err
			}
			v.FailureEventReporting = (*s00.FailureEventReportingCause)(bb.OwnInt64(int64(tmp_failureeventreporting)))

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
	v.Choice = 1
	switch v.Choice {
	case s00.SONtransferCauseChoiceCellLoadReporting:
		val_cellloadreporting, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellLoadReporting"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
		}
		tmp_cellloadreporting := s00.CellLoadReportingCause(val_cellloadreporting)
		if err := aper.ChargeValue(bb, tmp_cellloadreporting); err != nil {
			return err
		}
		v.CellLoadReporting = (*s00.CellLoadReportingCause)(bb.OwnInt64(int64(tmp_cellloadreporting)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes ReportingCellListItem to APER format.
func (v *ReportingCellListItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ReportingCellListItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeIRATCellIDMethodMarshalAPERTo(&v.CellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding cell-ID: %w", err)
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

// UnmarshalAPER decodes ReportingCellListItem from APER format.
func (v *ReportingCellListItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ReportingCellListItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ReportingCellListItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	bb.EnterComponent("ReportingCellListItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ReportingCellListItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellListItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ReportingCellListItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ReportingCellListItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_cellid := bb.EnterComponent("CellID")
	if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&v.CellID, bb); err != nil {
		return runtime.WrapDecodePath(err, "CellID")
	}
	bb.LeaveComponent(toleranceMark_cellid)
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
	bb.EnterComponent("NotificationCellListItem")
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ReportingCellListItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ReportingCellListItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ReportingCellListItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ReportingCellListItem) WithoutReplay() ReportingCellListItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ReportingCellListItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferCause) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferCause", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferCause", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferCause) WithoutReplay() SONtransferCause {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferCause
	v.perPadding = zero.perPadding
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

// Extensions returns owned unknown sequence additions.
func (v *ReportingCellListItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ReportingCellListItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ReportingCellListItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ReportingCellListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ReportingCellListItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ReportingCellListItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ReportingCellListItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ReportingCellListItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ReportingCellListItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ReportingCellListItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ReportingCellListItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APReportingCellListItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ReportingCellListItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ReportingCellListItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ReportingCellListItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ReportingCellListItem")
}
func (v *ReportingCellListItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ReportingCellListItem")
}
func (v *ReportingCellListItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APReportingCellListItem(v, &s)
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
func (v *ReportingCellListItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ReportingCellListItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONtransferCause) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferCause")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferCause) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferCause")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferCause(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferCause")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferCause")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferCause) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferCause")
}
func (v *SONtransferCause) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferCause")
}
func (v *SONtransferCause) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferCause(v, &s)
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
func (v *SONtransferCause) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferCause) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ReportingCellListItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ReportingCellListItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ReportingCellListItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APReportingCellListItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ReportingCellListItem{}
		return report, aper.OperationError(err, "ReportingCellListItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ReportingCellListItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferCause) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferCause")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferCause
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferCause(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferCause{}
		return report, aper.OperationError(err, "SONtransferCause")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferCause")
}

// NewCellLoadReportingResponseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewCellLoadReportingResponseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s18.CellLoadReportingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
	}
	value := s18.CellLoadReportingResponse{UnknownExtension: &extension}
	if _, err := s18.BridgeCellLoadReportingResponseMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s18.CellLoadReportingResponse{}, aper.OperationError(err, "CellLoadReportingResponseUnknownExtension")
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
func NewMultiCellLoadReportingResponseItemUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s19.MultiCellLoadReportingResponseItem, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	value := s19.MultiCellLoadReportingResponseItem{UnknownExtension: &extension}
	if _, err := s19.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s19.MultiCellLoadReportingResponseItem{}, aper.OperationError(err, "MultiCellLoadReportingResponseItemUnknownExtension")
	}
	return value, aper.OperationError(nil, "MultiCellLoadReportingResponseItemUnknownExtension")
}

// NewSONtransferCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferCauseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferCause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	value := SONtransferCause{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferCause{}, aper.OperationError(err, "SONtransferCauseUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferCauseUnknownExtension")
}

type SONInformationExtensionIEIEValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowSONInformationReport *SONInformationReport
}

func (v SONInformationExtensionIEIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(206):
		return v.rowSONInformationReport != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SONInformationExtensionIEIEValue and reports whether the opaque alternative is selected.
func (v *SONInformationExtensionIEIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SONInformationExtensionIEIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE"}}
}
func (SONInformationExtensionIEIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(206):
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

// AsSONInformationReport returns the selected SONInformationReport value of SONInformationExtensionIEIEValue and reports whether that alternative is active.
func (v *SONInformationExtensionIEIEValue) AsSONInformationReport() (*SONInformationReport, bool) {
	if v == nil || v.id != s00.ProtocolIEID(206) || v.rowSONInformationReport == nil {
		return nil, false
	}
	return v.rowSONInformationReport, true
}
func (v SONInformationExtensionIEIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SONInformationExtensionIEIEValue, error) {
	out := SONInformationExtensionIEIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(206):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SONInformationReport
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SONInformationReport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SONInformationReport")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSONInformationReport = &value
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
func (v SONInformationExtensionIEIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v SONInformationExtensionIEIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(206):
		if v.rowSONInformationReport == nil {
			return nil, fmt.Errorf("%s missing value", "SONInformation-ExtensionIE.id-SON-Information-Report:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSONInformationReport.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SONInformationExtensionIEIEValue:", v.id)
	}
}

type RerouteNASRequestIEValue struct {
	id                s00.ProtocolIEID
	received          aper.WireSpan
	replay            aper.Snapshot
	opaque            aper.OpaqueOpenType
	isOpaque          bool
	rowENBUES1APID    *s00.ENBUES1APID
	rowMMEUES1APID    *s00.MMEUES1APID
	rowS1Message      *[]byte
	rowMMEGroupID     *s00.MMEGroupID
	rowAdditionalGUTI *s18.AdditionalGUTI
	rowUEUsageType    *s00.UEUsageType
}

func (v RerouteNASRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(0):
		return v.rowMMEUES1APID != nil
	case s00.ProtocolIEID(225):
		return v.rowS1Message != nil
	case s00.ProtocolIEID(223):
		return v.rowMMEGroupID != nil
	case s00.ProtocolIEID(224):
		return v.rowAdditionalGUTI != nil
	case s00.ProtocolIEID(230):
		return v.rowUEUsageType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of RerouteNASRequestIEValue and reports whether the opaque alternative is selected.
func (v *RerouteNASRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (RerouteNASRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs"}}
}
func (RerouteNASRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(225):
		return aper.UnknownSelector
	case s00.ProtocolIEID(223):
		return aper.UnknownSelector
	case s00.ProtocolIEID(224):
		return aper.UnknownSelector
	case s00.ProtocolIEID(230):
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
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
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

// AsENBUES1APID returns the selected ENBUES1APID value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsMMEUES1APID returns the selected MMEUES1APID value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsS1Message returns the selected S1Message value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsS1Message() (*[]byte, bool) {
	if v == nil || v.id != s00.ProtocolIEID(225) || v.rowS1Message == nil {
		return nil, false
	}
	return v.rowS1Message, true
}

// AsMMEGroupID returns the selected MMEGroupID value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsMMEGroupID() (*s00.MMEGroupID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(223) || v.rowMMEGroupID == nil {
		return nil, false
	}
	return v.rowMMEGroupID, true
}

// AsAdditionalGUTI returns the selected AdditionalGUTI value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsAdditionalGUTI() (*s18.AdditionalGUTI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(224) || v.rowAdditionalGUTI == nil {
		return nil, false
	}
	return v.rowAdditionalGUTI, true
}

// AsUEUsageType returns the selected UEUsageType value of RerouteNASRequestIEValue and reports whether that alternative is active.
func (v *RerouteNASRequestIEValue) AsUEUsageType() (*s00.UEUsageType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(230) || v.rowUEUsageType == nil {
		return nil, false
	}
	return v.rowUEUsageType, true
}
func (v RerouteNASRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (RerouteNASRequestIEValue, error) {
	out := RerouteNASRequestIEValue{id: id}
	switch id {
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
	case s00.ProtocolIEID(225):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) ([]byte, error) {
			var v struct{ Value []byte }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = val_value
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
		out.rowS1Message = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(223):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MMEGroupID, error) {
			var v struct{ Value s00.MMEGroupID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.MMEGroupID(val_value)
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
		out.rowMMEGroupID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(224):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.AdditionalGUTI
		child := scope
		if err := s18.BridgeAdditionalGUTIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "AdditionalGUTI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AdditionalGUTI")
		if err != nil {
			return out, err
		}
		*s18.BridgeAdditionalGUTIFieldPerPadding(&value) = padding
		*s18.BridgeAdditionalGUTIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeAdditionalGUTIFieldReceivedBytes(&value))
		*s18.BridgeAdditionalGUTIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowAdditionalGUTI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(230):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
		value := s00.UEUsageType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEUsageType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEUsageType = &value
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
func (v RerouteNASRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v RerouteNASRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(0):
		if v.rowMMEUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-MME-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(225):
		if v.rowS1Message == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-S1-Message:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value []byte, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value []byte }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, v.Value, 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowS1Message, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(223):
		if v.rowMMEGroupID == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-MME-Group-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MMEGroupID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MMEGroupID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMMEGroupID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(224):
		if v.rowAdditionalGUTI == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-Additional-GUTI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeAdditionalGUTIMethodMarshalAPERBudget(v.rowAdditionalGUTI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(230):
		if v.rowUEUsageType == nil {
			return nil, fmt.Errorf("%s missing value", "RerouteNASRequest-IEs.id-UE-Usage-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowUEUsageType), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "RerouteNASRequestIEValue:", v.id)
	}
}

type S1RemovalRequestIEValue struct {
	id             s00.ProtocolIEID
	received       aper.WireSpan
	replay         aper.Snapshot
	opaque         aper.OpaqueOpenType
	isOpaque       bool
	rowGlobalENBID *s18.GlobalENBID
}

func (v S1RemovalRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(59):
		return v.rowGlobalENBID != nil
	}
	return false
}

// Opaque returns the retained opaque open value of S1RemovalRequestIEValue and reports whether the opaque alternative is selected.
func (v *S1RemovalRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (S1RemovalRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs"}}
}
func (S1RemovalRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(59):
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

// AsGlobalENBID returns the selected GlobalENBID value of S1RemovalRequestIEValue and reports whether that alternative is active.
func (v *S1RemovalRequestIEValue) AsGlobalENBID() (*s18.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}
func (v S1RemovalRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (S1RemovalRequestIEValue, error) {
	out := S1RemovalRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(59):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GlobalENBID
		child := scope
		if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GlobalENBID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalENBID")
		if err != nil {
			return out, err
		}
		*s18.BridgeGlobalENBIDFieldPerPadding(&value) = padding
		*s18.BridgeGlobalENBIDFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGlobalENBIDFieldReceivedBytes(&value))
		*s18.BridgeGlobalENBIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowGlobalENBID = &value
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
func (v S1RemovalRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v S1RemovalRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(59):
		if v.rowGlobalENBID == nil {
			return nil, fmt.Errorf("%s missing value", "S1RemovalRequestIEs.id-Global-ENB-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "S1RemovalRequestIEValue:", v.id)
	}
}

type SONInformationExtensionIETable struct{}

func SONInformationExtensionIE() SONInformationExtensionIETable {
	return SONInformationExtensionIETable{}
}

// ID returns the ASN.1 object-set identity of SONInformationExtensionIETable.
func (SONInformationExtensionIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SONInformationExtensionIETable.
func (SONInformationExtensionIETable) Table() s00.SONInformationExtensionIEIEValueIETable {
	return func() s00.SONInformationExtensionIEIEValueIETable {
		sealed := s00.SONInformationExtensionIEIEValueIETable{}
		*s00.BridgeSONInformationExtensionIEIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SONInformationExtensionIETable) infoSONInformationReport() s00.FieldInfo {
	return s00.FieldInfo{Table: SONInformationExtensionIE().ID(), ID: s00.ProtocolIEID(206), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReport"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformation-ExtensionIE", Row: "id-SON-Information-Report"}}}
}

// SONInformationReport returns the typed binding for the SONInformationReport row of SONInformationExtensionIETable.
func (t SONInformationExtensionIETable) SONInformationReport() SONInformationExtensionIESONInformationReportIEBinding {
	return SONInformationExtensionIESONInformationReportIEBinding{info: t.infoSONInformationReport(), codec: SONInformationReportValueCodec{path: "SONInformationReport",
		decode: func(data []byte, options aper.DecodeState) (SONInformationReport, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty SONInformationReport
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SONInformationReport")
			var zero SONInformationExtensionIEIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(206), raw)
			if err != nil {
				var empty SONInformationReport
				return empty, runtime.WrapDecodePath(err, "SONInformationReport")
			}
			value, ok := decoded.AsSONInformationReport()
			if !ok {
				var empty SONInformationReport
				return empty, fmt.Errorf("binding SONInformation-ExtensionIE.id-SON-Information-Report: no selected value")
			}
			return *value, nil
		},
		encode: func(value SONInformationReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONInformationExtensionIEIEValue{id: s00.ProtocolIEID(206), rowSONInformationReport: &value}).encodeFresh(fresh, budget)
		}, capture: func(v SONInformationReport, options aper.DecodeState) (SONInformationReport, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APSONInformationReport(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v SONInformationReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APSONInformationReport(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationReport"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value SONInformationReport) SONInformationExtensionIEIEValue {
		return SONInformationExtensionIEIEValue{id: s00.ProtocolIEID(206), rowSONInformationReport: &value}
	}, get: func(value *SONInformationExtensionIEIEValue) (*SONInformationReport, bool) {
		return value.AsSONInformationReport()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SONInformationExtensionIETable.
func (t SONInformationExtensionIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (SONInformationExtensionIEIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(206):
		return SONInformationExtensionIEIEField{}, aper.OperationError(fmt.Errorf("known IE id-SON-Information-Report requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SONInformationExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		return SONInformationExtensionIEIEField{Id: id, Criticality: criticality, Value: SONInformationExtensionIEIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type RerouteNASRequestIETable struct{}

func RerouteNASRequestIEs() RerouteNASRequestIETable { return RerouteNASRequestIETable{} }

// ID returns the ASN.1 object-set identity of RerouteNASRequestIETable.
func (RerouteNASRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by RerouteNASRequestIETable.
func (RerouteNASRequestIETable) Table() s00.RerouteNASRequestIEValueIETable {
	return func() s00.RerouteNASRequestIEValueIETable {
		sealed := s00.RerouteNASRequestIEValueIETable{}
		*s00.BridgeRerouteNASRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (RerouteNASRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) ENBUES1APID() RerouteNASRequestENBUES1APIDIEBinding {
	return RerouteNASRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (RerouteNASRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) MMEUES1APID() RerouteNASRequestMMEUES1APIDIEBinding {
	return RerouteNASRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (RerouteNASRequestIETable) infoS1Message() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(225), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "OCTET STRING"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-S1-Message"}}}
}

// S1Message returns the typed binding for the S1Message row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) S1Message() RerouteNASRequestSliceByteIEBinding {
	return RerouteNASRequestSliceByteIEBinding{info: t.infoS1Message(), codec: func() s01.SliceByteValueCodec {
		sealed := s01.SliceByteValueCodec{}
		*s01.BridgeSliceByteValueCodecFieldPath(&sealed) = "[]byte"
		*s01.BridgeSliceByteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) ([]byte, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty []byte
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("[]byte")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(225), raw)
			if err != nil {
				var empty []byte
				return empty, runtime.WrapDecodePath(err, "[]byte")
			}
			value, ok := decoded.AsS1Message()
			if !ok {
				var empty []byte
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-S1-Message: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSliceByteValueCodecFieldEncode(&sealed) = func(value []byte, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(225), rowS1Message: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSliceByteValueCodecFieldCapture(&sealed) = func(v []byte, options aper.DecodeState) ([]byte, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			func(v *[]byte, s *aper.SemanticCapture) {
				if s.Err() != nil {
					return
				}
				f := s.Begin()
				s.Bytes((*v))
				s.End(
					f, nil, false)
			}(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s01.BridgeSliceByteValueCodecFieldCompare(&sealed) = func(v []byte, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			func(v *[]byte, s *aper.SemanticComparison) {
				if s.Err() != nil {
					return

				}
				f := s.Begin()
				s.Bytes((*v))
				s.End(f, aper.Snapshot{}, false)
			}(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSliceByteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:[]byte"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value []byte) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(225), rowS1Message: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*[]byte, bool) { return value.AsS1Message() }}
}
func (RerouteNASRequestIETable) infoMMEGroupID() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(223), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-Group-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-MME-Group-ID"}}}
}

// MMEGroupID returns the typed binding for the MMEGroupID row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) MMEGroupID() RerouteNASRequestMMEGroupIDIEBinding {
	return RerouteNASRequestMMEGroupIDIEBinding{info: t.infoMMEGroupID(), codec: func() s01.MMEGroupIDValueCodec {
		sealed := s01.MMEGroupIDValueCodec{}
		*s01.BridgeMMEGroupIDValueCodecFieldPath(&sealed) = "MMEGroupID"
		*s01.BridgeMMEGroupIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEGroupID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEGroupID")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(223), raw)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, runtime.WrapDecodePath(err, "MMEGroupID")
			}
			value, ok := decoded.AsMMEGroupID()
			if !ok {
				var empty s00.MMEGroupID
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-MME-Group-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEGroupIDValueCodecFieldEncode(&sealed) = func(value s00.MMEGroupID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(223), rowMMEGroupID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCapture(&sealed) = func(v s00.MMEGroupID, options aper.DecodeState) (s00.MMEGroupID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEGroupID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCompare(&sealed) = func(v s00.MMEGroupID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEGroupID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEGroupIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEGroupID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEGroupID) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(223), rowMMEGroupID: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*s00.MMEGroupID, bool) { return value.AsMMEGroupID() }}
}
func (RerouteNASRequestIETable) infoAdditionalGUTI() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(224), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Additional-GUTI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-Additional-GUTI"}}}
}

// AdditionalGUTI returns the typed binding for the AdditionalGUTI row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) AdditionalGUTI() RerouteNASRequestAdditionalGUTIIEBinding {
	return RerouteNASRequestAdditionalGUTIIEBinding{info: t.infoAdditionalGUTI(), codec: func() s18.AdditionalGUTIValueCodec {
		sealed := s18.AdditionalGUTIValueCodec{}
		*s18.BridgeAdditionalGUTIValueCodecFieldPath(&sealed) = "AdditionalGUTI"
		*s18.BridgeAdditionalGUTIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.AdditionalGUTI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.AdditionalGUTI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalGUTI")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(224), raw)
			if err != nil {
				var empty s18.AdditionalGUTI
				return empty, runtime.WrapDecodePath(err, "AdditionalGUTI")
			}
			value, ok := decoded.AsAdditionalGUTI()
			if !ok {
				var empty s18.AdditionalGUTI
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-Additional-GUTI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeAdditionalGUTIValueCodecFieldEncode(&sealed) = func(value s18.AdditionalGUTI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(224), rowAdditionalGUTI: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeAdditionalGUTIValueCodecFieldCapture(&sealed) = func(v s18.AdditionalGUTI, options aper.DecodeState) (s18.AdditionalGUTI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APAdditionalGUTI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeAdditionalGUTIValueCodecFieldCompare(&sealed) = func(v s18.AdditionalGUTI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APAdditionalGUTI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeAdditionalGUTIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalGUTI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.AdditionalGUTI) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(224), rowAdditionalGUTI: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*s18.AdditionalGUTI, bool) { return value.AsAdditionalGUTI() }}
}
func (RerouteNASRequestIETable) infoUEUsageType() s00.FieldInfo {
	return s00.FieldInfo{Table: RerouteNASRequestIEs().ID(), ID: s00.ProtocolIEID(230), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Usage-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "RerouteNASRequest-IEs", Row: "id-UE-Usage-Type"}}}
}

// UEUsageType returns the typed binding for the UEUsageType row of RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) UEUsageType() RerouteNASRequestUEUsageTypeIEBinding {
	return RerouteNASRequestUEUsageTypeIEBinding{info: t.infoUEUsageType(), codec: func() s02.UEUsageTypeValueCodec {
		sealed := s02.UEUsageTypeValueCodec{}
		*s02.BridgeUEUsageTypeValueCodecFieldPath(&sealed) = "UEUsageType"
		*s02.BridgeUEUsageTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUsageType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUsageType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEUsageType")
			var zero RerouteNASRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(230), raw)
			if err != nil {
				var empty s00.UEUsageType
				return empty, runtime.WrapDecodePath(err, "UEUsageType")
			}
			value, ok := decoded.AsUEUsageType()
			if !ok {
				var empty s00.UEUsageType
				return empty, fmt.Errorf("binding RerouteNASRequest-IEs.id-UE-Usage-Type: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUsageTypeValueCodecFieldEncode(&sealed) = func(value s00.UEUsageType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (RerouteNASRequestIEValue{id: s00.ProtocolIEID(230), rowUEUsageType: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCapture(&sealed) = func(v s00.UEUsageType, options aper.DecodeState) (s00.UEUsageType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEUsageType(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCompare(&sealed) = func(v s00.UEUsageType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEUsageType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeUEUsageTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUsageType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEUsageType) RerouteNASRequestIEValue {
			return RerouteNASRequestIEValue{id: s00.ProtocolIEID(230), rowUEUsageType: &value}
		}, get: func(value *RerouteNASRequestIEValue) (*s00.UEUsageType, bool) { return value.AsUEUsageType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in RerouteNASRequestIETable.
func (t RerouteNASRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (RerouteNASRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(0):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(225):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-S1-Message requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(223):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-Group-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(224):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Additional-GUTI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(230):
		return RerouteNASRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Usage-Type requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return RerouteNASRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return RerouteNASRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return RerouteNASRequestIEField{Id: id, Criticality: criticality, Value: RerouteNASRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type S1RemovalRequestIETable struct{}

func S1RemovalRequestIEs() S1RemovalRequestIETable { return S1RemovalRequestIETable{} }

// ID returns the ASN.1 object-set identity of S1RemovalRequestIETable.
func (S1RemovalRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by S1RemovalRequestIETable.
func (S1RemovalRequestIETable) Table() s00.S1RemovalRequestIEValueIETable {
	return func() s00.S1RemovalRequestIEValueIETable {
		sealed := s00.S1RemovalRequestIEValueIETable{}
		*s00.BridgeS1RemovalRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (S1RemovalRequestIETable) infoGlobalENBID() s00.FieldInfo {
	return s00.FieldInfo{Table: S1RemovalRequestIEs().ID(), ID: s00.ProtocolIEID(59), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-ENB-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "S1RemovalRequestIEs", Row: "id-Global-ENB-ID"}}}
}

// GlobalENBID returns the typed binding for the GlobalENBID row of S1RemovalRequestIETable.
func (t S1RemovalRequestIETable) GlobalENBID() S1RemovalRequestGlobalENBIDIEBinding {
	return S1RemovalRequestGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s18.GlobalENBIDValueCodec {
		sealed := s18.GlobalENBIDValueCodec{}
		*s18.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s18.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero S1RemovalRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s18.GlobalENBID
				return empty, fmt.Errorf("binding S1RemovalRequestIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s18.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (S1RemovalRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGlobalENBIDValueCodecFieldCapture(&sealed) = func(v s18.GlobalENBID, options aper.DecodeState) (s18.GlobalENBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APGlobalENBID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGlobalENBIDValueCodecFieldCompare(&sealed) = func(v s18.GlobalENBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APGlobalENBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s18.BridgeGlobalENBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalENBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GlobalENBID) S1RemovalRequestIEValue {
			return S1RemovalRequestIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *S1RemovalRequestIEValue) (*s18.GlobalENBID, bool) { return value.AsGlobalENBID() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in S1RemovalRequestIETable.
func (t S1RemovalRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (S1RemovalRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(59):
		return S1RemovalRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Global-ENB-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return S1RemovalRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return S1RemovalRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return S1RemovalRequestIEField{Id: id, Criticality: criticality, Value: S1RemovalRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AdditionalGUTICodec binds the complete APER value type.
func AdditionalGUTICodec() s18.AdditionalGUTIValueCodec {
	return RerouteNASRequestIEs().AdditionalGUTI().Codec()
}

// LastVisitedPSCellInformationCodec binds the complete source value type.
func LastVisitedPSCellInformationCodec() LastVisitedPSCellInformationValueCodec {
	return LastVisitedPSCellInformationValueCodec{path: "LastVisitedPSCellInformation", decode: func(data []byte, options aper.DecodeState) (LastVisitedPSCellInformation, error) {
		var value LastVisitedPSCellInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LastVisitedPSCellInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LastVisitedPSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LastVisitedPSCellInformation, options aper.DecodeState) (LastVisitedPSCellInformation, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APLastVisitedPSCellInformation(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v LastVisitedPSCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APLastVisitedPSCellInformation(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedPSCellInformation"
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

// PC5QoSFlowItemCodec binds the complete source value type.
func PC5QoSFlowItemCodec() PC5QoSFlowItemValueCodec {
	return PC5QoSFlowItemValueCodec{path: "PC5QoSFlowItem", decode: func(data []byte, options aper.DecodeState) (PC5QoSFlowItem, error) {
		var value PC5QoSFlowItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PC5QoSFlowItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PC5QoSFlowItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PC5QoSFlowItem, options aper.DecodeState) (PC5QoSFlowItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APPC5QoSFlowItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PC5QoSFlowItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPC5QoSFlowItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSFlowItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PLMNAreaBasedQMCCodec binds the complete source value type.
func PLMNAreaBasedQMCCodec() PLMNAreaBasedQMCValueCodec {
	return PLMNAreaBasedQMCValueCodec{path: "PLMNAreaBasedQMC", decode: func(data []byte, options aper.DecodeState) (PLMNAreaBasedQMC, error) {
		var value PLMNAreaBasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PLMNAreaBasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PLMNAreaBasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PLMNAreaBasedQMC, options aper.DecodeState) (PLMNAreaBasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APPLMNAreaBasedQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PLMNAreaBasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPLMNAreaBasedQMC(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PLMNAreaBasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PagingAttemptInformationCodec binds the complete source value type.
func PagingAttemptInformationCodec() PagingAttemptInformationValueCodec {
	return PagingAttemptInformationValueCodec{path: "PagingAttemptInformation", decode: func(data []byte, options aper.DecodeState) (PagingAttemptInformation, error) {
		var value PagingAttemptInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PagingAttemptInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PagingAttemptInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PagingAttemptInformation, options aper.DecodeState) (PagingAttemptInformation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APPagingAttemptInformation(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v PagingAttemptInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPagingAttemptInformation(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingAttemptInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// PrivacyIndicatorCodec binds the complete APER value type.
func PrivacyIndicatorCodec() s01.PrivacyIndicatorValueCodec {
	return s18.CellTrafficTraceIEs().PrivacyIndicator().Codec()
}

// PrivateIEIDCodec binds the complete source value type.
func PrivateIEIDCodec() PrivateIEIDValueCodec {
	return PrivateIEIDValueCodec{path: "PrivateIEID", decode: func(data []byte, options aper.DecodeState) (PrivateIEID, error) {
		var value PrivateIEID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PrivateIEID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PrivateIEID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PrivateIEID, options aper.DecodeState) (PrivateIEID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APPrivateIEID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PrivateIEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APPrivateIEID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// RATRestrictionsItemCodec binds the complete source value type.
func RATRestrictionsItemCodec() RATRestrictionsItemValueCodec {
	return RATRestrictionsItemValueCodec{path: "RATRestrictionsItem", decode: func(data []byte, options aper.DecodeState) (RATRestrictionsItem, error) {
		var value RATRestrictionsItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RATRestrictionsItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RATRestrictionsItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RATRestrictionsItem, options aper.DecodeState) (RATRestrictionsItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRATRestrictionsItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v RATRestrictionsItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRATRestrictionsItem(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RATRestrictionsItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// RLFReportInformationCodec binds the complete source value type.
func RLFReportInformationCodec() RLFReportInformationValueCodec {
	return RLFReportInformationValueCodec{path: "RLFReportInformation", decode: func(data []byte, options aper.DecodeState) (RLFReportInformation, error) {
		var value RLFReportInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RLFReportInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RLFReportInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RLFReportInformation, options aper.DecodeState) (RLFReportInformation, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRLFReportInformation(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v RLFReportInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRLFReportInformation(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RLFReportInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ReceiveStatusOfULPDCPSDUsExtendedCodec binds the complete APER value type.
func ReceiveStatusOfULPDCPSDUsExtendedCodec() s01.ReceiveStatusOfULPDCPSDUsExtendedValueCodec {
	return s14.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsExtended().Codec()
}

// ReceiveStatusOfULPDCPSDUsPDCPSNlength18Codec binds the complete APER value type.
func ReceiveStatusOfULPDCPSDUsPDCPSNlength18Codec() s01.ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec {
	return s14.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsPDCPSNlength18().Codec()
}

// ReportingCellListItemCodec binds the complete source value type.
func ReportingCellListItemCodec() ReportingCellListItemValueCodec {
	return ReportingCellListItemValueCodec{path: "ReportingCellListItem", decode: func(data []byte, options aper.DecodeState) (ReportingCellListItem, error) {
		var value ReportingCellListItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ReportingCellListItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ReportingCellListItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ReportingCellListItem, options aper.DecodeState) (ReportingCellListItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APReportingCellListItem(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v ReportingCellListItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APReportingCellListItem(&v, &s)
		s.End(f, root, false)

		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportingCellListItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONInformationExtensionCodec binds the complete source value type.
func SONInformationExtensionCodec() SONInformationExtensionValueCodec {
	return SONInformationExtensionValueCodec{path: "SONInformationExtension", decode: func(data []byte, options aper.DecodeState) (SONInformationExtension, error) {
		var value SONInformationExtension
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONInformationExtension{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONInformationExtension, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONInformationExtension, options aper.DecodeState) (SONInformationExtension, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONInformationExtension(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false,
		)
		return v, root
	}, compare: func(v SONInformationExtension, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONInformationExtension(&v, &s)
		s.End(f, root,
			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationExtension"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONInformationReportCodec binds the complete APER value type.
func SONInformationReportCodec() SONInformationReportValueCodec {
	return SONInformationExtensionIE().SONInformationReport().Codec()
}

// SONtransferCauseCodec binds the complete source value type.
func SONtransferCauseCodec() SONtransferCauseValueCodec {
	return SONtransferCauseValueCodec{path: "SONtransferCause", decode: func(data []byte, options aper.DecodeState) (SONtransferCause, error) {
		var value SONtransferCause
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferCause{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferCause, options aper.DecodeState) (SONtransferCause, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferCause(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONtransferCause(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferCause"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SourceNodeIDExtensionCodec binds the complete source value type.
func SourceNodeIDExtensionCodec() SourceNodeIDExtensionValueCodec {
	return SourceNodeIDExtensionValueCodec{path: "SourceNodeIDExtension", decode: func(data []byte, options aper.DecodeState) (SourceNodeIDExtension, error) {
		var value SourceNodeIDExtension
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SourceNodeIDExtension{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SourceNodeIDExtension, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SourceNodeIDExtension, options aper.DecodeState) (SourceNodeIDExtension, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSourceNodeIDExtension(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)

		return v, root
	}, compare: func(v SourceNodeIDExtension, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSourceNodeIDExtension(&v, &s)
		s.End(f, root, false)

		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNodeIDExtension"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeLastVisitedPSCellInformationAPERValueFieldContext(v *LastVisitedPSCellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellInformationAPERValueFieldReceived(v *LastVisitedPSCellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedPSCellInformationAPERValueFieldReplay(v *LastVisitedPSCellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedPSCellInformationAPERValueFieldWithoutReplay(v *LastVisitedPSCellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedPSCellInformationFieldExtCount(v *LastVisitedPSCellInformation) *int64 {
	return &v.extCount
}
func BridgeLastVisitedPSCellInformationFieldExtData(v *LastVisitedPSCellInformation) *[][]byte {
	return &v.extData
}
func BridgeLastVisitedPSCellInformationFieldExtOrigin(v *LastVisitedPSCellInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeLastVisitedPSCellInformationFieldExtPresent(v *LastVisitedPSCellInformation) *[]bool {
	return &v.extPresent
}
func BridgeLastVisitedPSCellInformationFieldExtWire(v *LastVisitedPSCellInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeLastVisitedPSCellInformationFieldIEExtensionsIndef(v *LastVisitedPSCellInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeLastVisitedPSCellInformationFieldPerExtPadding(v *LastVisitedPSCellInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLastVisitedPSCellInformationFieldPerPadding(v *LastVisitedPSCellInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeLastVisitedPSCellInformationFieldReceived(v *LastVisitedPSCellInformation) *bool {
	return &v.received
}
func BridgeLastVisitedPSCellInformationFieldReceivedAbsolute(v *LastVisitedPSCellInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeLastVisitedPSCellInformationFieldReceivedBytes(v *LastVisitedPSCellInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLastVisitedPSCellInformationFieldReceivedLocation(v *LastVisitedPSCellInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeLastVisitedPSCellInformationFieldReplay(v *LastVisitedPSCellInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedPSCellInformationFieldStream(v *LastVisitedPSCellInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeLastVisitedPSCellInformationFieldWithoutReplay(v *LastVisitedPSCellInformation) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERBudget(v *LastVisitedPSCellInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERBudgetValue(v *LastVisitedPSCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERChanged(v *LastVisitedPSCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERChangedValue(v *LastVisitedPSCellInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERLegacy(v *LastVisitedPSCellInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERNewValue(v *LastVisitedPSCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERPlanned(v *LastVisitedPSCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLastVisitedPSCellInformationMethodMarshalAPERTo(v *LastVisitedPSCellInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLastVisitedPSCellInformationMethodUnmarshalAPERFrom(v *LastVisitedPSCellInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLastVisitedPSCellInformationMethodUnmarshalAPERLegacy(v *LastVisitedPSCellInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLastVisitedPSCellInformationMethodUnmarshalAPERWithOptions(v *LastVisitedPSCellInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLastVisitedPSCellInformationValueCodecFieldCapture(v *LastVisitedPSCellInformationValueCodec) *func(LastVisitedPSCellInformation, aper.DecodeState) (LastVisitedPSCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedPSCellInformationValueCodecFieldCompare(v *LastVisitedPSCellInformationValueCodec) *func(LastVisitedPSCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedPSCellInformationValueCodecFieldContext(v *LastVisitedPSCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellInformationValueCodecFieldDecode(v *LastVisitedPSCellInformationValueCodec) *func([]byte, aper.DecodeState) (LastVisitedPSCellInformation, error) {
	return &v.decode
}
func BridgeLastVisitedPSCellInformationValueCodecFieldEncode(v *LastVisitedPSCellInformationValueCodec) *func(LastVisitedPSCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedPSCellInformationValueCodecFieldPath(v *LastVisitedPSCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedPSCellInformationValueCodecMethodEncodeBudgetValue(v LastVisitedPSCellInformationValueCodec, a0 LastVisitedPSCellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedPSCellInformationValueCodecMethodEncodeChanged(v LastVisitedPSCellInformationValueCodec, a0 LastVisitedPSCellInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLastVisitedPSCellListAPERValueFieldContext(v *LastVisitedPSCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellListAPERValueFieldReceived(v *LastVisitedPSCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLastVisitedPSCellListAPERValueFieldReplay(v *LastVisitedPSCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLastVisitedPSCellListAPERValueFieldWithoutReplay(v *LastVisitedPSCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLastVisitedPSCellListValueCodecFieldCapture(v *LastVisitedPSCellListValueCodec) *func(LastVisitedPSCellList, aper.DecodeState) (LastVisitedPSCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedPSCellListValueCodecFieldCompare(v *LastVisitedPSCellListValueCodec) *func(LastVisitedPSCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedPSCellListValueCodecFieldContext(v *LastVisitedPSCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedPSCellListValueCodecFieldDecode(v *LastVisitedPSCellListValueCodec) *func([]byte, aper.DecodeState) (LastVisitedPSCellList, error) {
	return &v.decode
}
func BridgeLastVisitedPSCellListValueCodecFieldEncode(v *LastVisitedPSCellListValueCodec) *func(LastVisitedPSCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedPSCellListValueCodecFieldPath(v *LastVisitedPSCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedPSCellListValueCodecMethodEncodeBudgetValue(v LastVisitedPSCellListValueCodec, a0 LastVisitedPSCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLastVisitedPSCellListValueCodecMethodEncodeChanged(v LastVisitedPSCellListValueCodec, a0 LastVisitedPSCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgePC5QoSFlowItemAPERValueFieldContext(v *PC5QoSFlowItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowItemAPERValueFieldReceived(v *PC5QoSFlowItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePC5QoSFlowItemAPERValueFieldReplay(v *PC5QoSFlowItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSFlowItemAPERValueFieldWithoutReplay(v *PC5QoSFlowItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSFlowItemFieldExtCount(v *PC5QoSFlowItem) *int64                { return &v.extCount }
func BridgePC5QoSFlowItemFieldExtData(v *PC5QoSFlowItem) *[][]byte              { return &v.extData }
func BridgePC5QoSFlowItemFieldExtOrigin(v *PC5QoSFlowItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgePC5QoSFlowItemFieldExtPresent(v *PC5QoSFlowItem) *[]bool             { return &v.extPresent }
func BridgePC5QoSFlowItemFieldExtWire(v *PC5QoSFlowItem) *[]aper.WireSpan       { return &v.extWire }
func BridgePC5QoSFlowItemFieldIEExtensionsIndef(v *PC5QoSFlowItem) *bool        { return &v.iEExtensionsIndef }
func BridgePC5QoSFlowItemFieldPerExtPadding(v *PC5QoSFlowItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePC5QoSFlowItemFieldPerPadding(v *PC5QoSFlowItem) *aper.FinalPadding { return &v.perPadding }
func BridgePC5QoSFlowItemFieldReceived(v *PC5QoSFlowItem) *bool                { return &v.received }
func BridgePC5QoSFlowItemFieldReceivedAbsolute(v *PC5QoSFlowItem) *bool        { return &v.receivedAbsolute }
func BridgePC5QoSFlowItemFieldReceivedBytes(v *PC5QoSFlowItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePC5QoSFlowItemFieldReceivedLocation(v *PC5QoSFlowItem) *aper.Location {
	return &v.receivedLocation
}
func BridgePC5QoSFlowItemFieldReplay(v *PC5QoSFlowItem) *aper.Snapshot { return &v.replay }
func BridgePC5QoSFlowItemFieldStream(v *PC5QoSFlowItem) *aper.WireSpan { return &v.stream }
func BridgePC5QoSFlowItemFieldWithoutReplay(v *PC5QoSFlowItem) *bool   { return &v.withoutReplay }
func BridgePC5QoSFlowItemMethodMarshalAPERBudget(v *PC5QoSFlowItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePC5QoSFlowItemMethodMarshalAPERBudgetValue(v *PC5QoSFlowItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePC5QoSFlowItemMethodMarshalAPERChanged(v *PC5QoSFlowItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePC5QoSFlowItemMethodMarshalAPERChangedValue(v *PC5QoSFlowItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePC5QoSFlowItemMethodMarshalAPERLegacy(v *PC5QoSFlowItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePC5QoSFlowItemMethodMarshalAPERNewValue(v *PC5QoSFlowItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePC5QoSFlowItemMethodMarshalAPERPlanned(v *PC5QoSFlowItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePC5QoSFlowItemMethodMarshalAPERTo(v *PC5QoSFlowItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePC5QoSFlowItemMethodUnmarshalAPERFrom(v *PC5QoSFlowItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5QoSFlowItemMethodUnmarshalAPERLegacy(v *PC5QoSFlowItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePC5QoSFlowItemMethodUnmarshalAPERWithOptions(v *PC5QoSFlowItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePC5QoSFlowItemValueCodecFieldCapture(v *PC5QoSFlowItemValueCodec) *func(PC5QoSFlowItem, aper.DecodeState) (PC5QoSFlowItem, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSFlowItemValueCodecFieldCompare(v *PC5QoSFlowItemValueCodec) *func(PC5QoSFlowItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSFlowItemValueCodecFieldContext(v *PC5QoSFlowItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowItemValueCodecFieldDecode(v *PC5QoSFlowItemValueCodec) *func([]byte, aper.DecodeState) (PC5QoSFlowItem, error) {
	return &v.decode
}
func BridgePC5QoSFlowItemValueCodecFieldEncode(v *PC5QoSFlowItemValueCodec) *func(PC5QoSFlowItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSFlowItemValueCodecFieldPath(v *PC5QoSFlowItemValueCodec) *aper.Path { return &v.path }
func BridgePC5QoSFlowItemValueCodecMethodEncodeBudgetValue(v PC5QoSFlowItemValueCodec, a0 PC5QoSFlowItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePC5QoSFlowItemValueCodecMethodEncodeChanged(v PC5QoSFlowItemValueCodec, a0 PC5QoSFlowItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePC5QoSFlowListAPERValueFieldContext(v *PC5QoSFlowListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowListAPERValueFieldReceived(v *PC5QoSFlowListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePC5QoSFlowListAPERValueFieldReplay(v *PC5QoSFlowListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSFlowListAPERValueFieldWithoutReplay(v *PC5QoSFlowListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSFlowListValueCodecFieldCapture(v *PC5QoSFlowListValueCodec) *func(PC5QoSFlowList, aper.DecodeState) (PC5QoSFlowList, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSFlowListValueCodecFieldCompare(v *PC5QoSFlowListValueCodec) *func(PC5QoSFlowList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSFlowListValueCodecFieldContext(v *PC5QoSFlowListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSFlowListValueCodecFieldDecode(v *PC5QoSFlowListValueCodec) *func([]byte, aper.DecodeState) (PC5QoSFlowList, error) {
	return &v.decode
}
func BridgePC5QoSFlowListValueCodecFieldEncode(v *PC5QoSFlowListValueCodec) *func(PC5QoSFlowList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSFlowListValueCodecFieldPath(v *PC5QoSFlowListValueCodec) *aper.Path { return &v.path }
func BridgePC5QoSFlowListValueCodecMethodEncodeBudgetValue(v PC5QoSFlowListValueCodec, a0 PC5QoSFlowList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePC5QoSFlowListValueCodecMethodEncodeChanged(v PC5QoSFlowListValueCodec, a0 PC5QoSFlowList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePLMNAreaBasedQMCAPERValueFieldContext(v *PLMNAreaBasedQMCAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNAreaBasedQMCAPERValueFieldReceived(v *PLMNAreaBasedQMCAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePLMNAreaBasedQMCAPERValueFieldReplay(v *PLMNAreaBasedQMCAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePLMNAreaBasedQMCAPERValueFieldWithoutReplay(v *PLMNAreaBasedQMCAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePLMNAreaBasedQMCFieldExtCount(v *PLMNAreaBasedQMC) *int64   { return &v.extCount }
func BridgePLMNAreaBasedQMCFieldExtData(v *PLMNAreaBasedQMC) *[][]byte { return &v.extData }
func BridgePLMNAreaBasedQMCFieldExtOrigin(v *PLMNAreaBasedQMC) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePLMNAreaBasedQMCFieldExtPresent(v *PLMNAreaBasedQMC) *[]bool       { return &v.extPresent }
func BridgePLMNAreaBasedQMCFieldExtWire(v *PLMNAreaBasedQMC) *[]aper.WireSpan { return &v.extWire }
func BridgePLMNAreaBasedQMCFieldIEExtensionsIndef(v *PLMNAreaBasedQMC) *bool {
	return &v.iEExtensionsIndef
}
func BridgePLMNAreaBasedQMCFieldPerExtPadding(v *PLMNAreaBasedQMC) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePLMNAreaBasedQMCFieldPerPadding(v *PLMNAreaBasedQMC) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePLMNAreaBasedQMCFieldPlmnListforQMCIndef(v *PLMNAreaBasedQMC) *bool {
	return &v.plmnListforQMCIndef
}
func BridgePLMNAreaBasedQMCFieldReceived(v *PLMNAreaBasedQMC) *bool { return &v.received }
func BridgePLMNAreaBasedQMCFieldReceivedAbsolute(v *PLMNAreaBasedQMC) *bool {
	return &v.receivedAbsolute
}
func BridgePLMNAreaBasedQMCFieldReceivedBytes(v *PLMNAreaBasedQMC) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePLMNAreaBasedQMCFieldReceivedLocation(v *PLMNAreaBasedQMC) *aper.Location {
	return &v.receivedLocation
}
func BridgePLMNAreaBasedQMCFieldReplay(v *PLMNAreaBasedQMC) *aper.Snapshot { return &v.replay }
func BridgePLMNAreaBasedQMCFieldStream(v *PLMNAreaBasedQMC) *aper.WireSpan { return &v.stream }
func BridgePLMNAreaBasedQMCFieldWithoutReplay(v *PLMNAreaBasedQMC) *bool   { return &v.withoutReplay }
func BridgePLMNAreaBasedQMCMethodMarshalAPERBudget(v *PLMNAreaBasedQMC, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERBudgetValue(v *PLMNAreaBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERChanged(v *PLMNAreaBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERChangedValue(v *PLMNAreaBasedQMC, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERLegacy(v *PLMNAreaBasedQMC) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERNewValue(v *PLMNAreaBasedQMC, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERPlanned(v *PLMNAreaBasedQMC, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePLMNAreaBasedQMCMethodMarshalAPERTo(v *PLMNAreaBasedQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePLMNAreaBasedQMCMethodUnmarshalAPERFrom(v *PLMNAreaBasedQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePLMNAreaBasedQMCMethodUnmarshalAPERLegacy(v *PLMNAreaBasedQMC, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePLMNAreaBasedQMCMethodUnmarshalAPERWithOptions(v *PLMNAreaBasedQMC, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePLMNAreaBasedQMCValueCodecFieldCapture(v *PLMNAreaBasedQMCValueCodec) *func(PLMNAreaBasedQMC, aper.DecodeState) (PLMNAreaBasedQMC, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNAreaBasedQMCValueCodecFieldCompare(v *PLMNAreaBasedQMCValueCodec) *func(PLMNAreaBasedQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePLMNAreaBasedQMCValueCodecFieldContext(v *PLMNAreaBasedQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNAreaBasedQMCValueCodecFieldDecode(v *PLMNAreaBasedQMCValueCodec) *func([]byte, aper.DecodeState) (PLMNAreaBasedQMC, error) {
	return &v.decode
}
func BridgePLMNAreaBasedQMCValueCodecFieldEncode(v *PLMNAreaBasedQMCValueCodec) *func(PLMNAreaBasedQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNAreaBasedQMCValueCodecFieldPath(v *PLMNAreaBasedQMCValueCodec) *aper.Path {
	return &v.path
}
func BridgePLMNAreaBasedQMCValueCodecMethodEncodeBudgetValue(v PLMNAreaBasedQMCValueCodec, a0 PLMNAreaBasedQMC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePLMNAreaBasedQMCValueCodecMethodEncodeChanged(v PLMNAreaBasedQMCValueCodec, a0 PLMNAreaBasedQMC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePSCellInformationAPERValueFieldContext(v *PSCellInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePSCellInformationAPERValueFieldReceived(v *PSCellInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePSCellInformationAPERValueFieldReplay(v *PSCellInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePSCellInformationAPERValueFieldWithoutReplay(v *PSCellInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePSCellInformationFieldExtCount(v *PSCellInformation) *int64   { return &v.extCount }
func BridgePSCellInformationFieldExtData(v *PSCellInformation) *[][]byte { return &v.extData }
func BridgePSCellInformationFieldExtOrigin(v *PSCellInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePSCellInformationFieldExtPresent(v *PSCellInformation) *[]bool       { return &v.extPresent }
func BridgePSCellInformationFieldExtWire(v *PSCellInformation) *[]aper.WireSpan { return &v.extWire }
func BridgePSCellInformationFieldIEExtensionsIndef(v *PSCellInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgePSCellInformationFieldPerExtPadding(v *PSCellInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePSCellInformationFieldPerPadding(v *PSCellInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePSCellInformationFieldReceived(v *PSCellInformation) *bool { return &v.received }
func BridgePSCellInformationFieldReceivedAbsolute(v *PSCellInformation) *bool {
	return &v.receivedAbsolute
}
func BridgePSCellInformationFieldReceivedBytes(v *PSCellInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePSCellInformationFieldReceivedLocation(v *PSCellInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgePSCellInformationFieldReplay(v *PSCellInformation) *aper.Snapshot { return &v.replay }
func BridgePSCellInformationFieldStream(v *PSCellInformation) *aper.WireSpan { return &v.stream }
func BridgePSCellInformationFieldWithoutReplay(v *PSCellInformation) *bool   { return &v.withoutReplay }
func BridgePSCellInformationMethodMarshalAPERBudget(v *PSCellInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePSCellInformationMethodMarshalAPERBudgetValue(v *PSCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePSCellInformationMethodMarshalAPERChanged(v *PSCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePSCellInformationMethodMarshalAPERChangedValue(v *PSCellInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePSCellInformationMethodMarshalAPERLegacy(v *PSCellInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePSCellInformationMethodMarshalAPERNewValue(v *PSCellInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePSCellInformationMethodMarshalAPERPlanned(v *PSCellInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePSCellInformationMethodMarshalAPERTo(v *PSCellInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePSCellInformationMethodUnmarshalAPERFrom(v *PSCellInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePSCellInformationMethodUnmarshalAPERLegacy(v *PSCellInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePSCellInformationMethodUnmarshalAPERWithOptions(v *PSCellInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePSCellInformationValueCodecFieldCapture(v *PSCellInformationValueCodec) *func(PSCellInformation, aper.DecodeState) (PSCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgePSCellInformationValueCodecFieldCompare(v *PSCellInformationValueCodec) *func(PSCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePSCellInformationValueCodecFieldContext(v *PSCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePSCellInformationValueCodecFieldDecode(v *PSCellInformationValueCodec) *func([]byte, aper.DecodeState) (PSCellInformation, error) {
	return &v.decode
}
func BridgePSCellInformationValueCodecFieldEncode(v *PSCellInformationValueCodec) *func(PSCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePSCellInformationValueCodecFieldPath(v *PSCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgePSCellInformationValueCodecMethodEncodeBudgetValue(v PSCellInformationValueCodec, a0 PSCellInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePSCellInformationValueCodecMethodEncodeChanged(v PSCellInformationValueCodec, a0 PSCellInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSfailedECGIListAPERValueFieldContext(v *PWSfailedECGIListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSfailedECGIListAPERValueFieldReceived(v *PWSfailedECGIListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSfailedECGIListAPERValueFieldReplay(v *PWSfailedECGIListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSfailedECGIListAPERValueFieldWithoutReplay(v *PWSfailedECGIListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSfailedECGIListValueCodecFieldCapture(v *PWSfailedECGIListValueCodec) *func(PWSfailedECGIList, aper.DecodeState) (PWSfailedECGIList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSfailedECGIListValueCodecFieldCompare(v *PWSfailedECGIListValueCodec) *func(PWSfailedECGIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSfailedECGIListValueCodecFieldContext(v *PWSfailedECGIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSfailedECGIListValueCodecFieldDecode(v *PWSfailedECGIListValueCodec) *func([]byte, aper.DecodeState) (PWSfailedECGIList, error) {
	return &v.decode
}
func BridgePWSfailedECGIListValueCodecFieldEncode(v *PWSfailedECGIListValueCodec) *func(PWSfailedECGIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSfailedECGIListValueCodecFieldPath(v *PWSfailedECGIListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSfailedECGIListValueCodecMethodEncodeBudgetValue(v PWSfailedECGIListValueCodec, a0 PWSfailedECGIList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSfailedECGIListValueCodecMethodEncodeChanged(v PWSfailedECGIListValueCodec, a0 PWSfailedECGIList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingAttemptInformationAPERValueFieldContext(v *PagingAttemptInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingAttemptInformationAPERValueFieldReceived(v *PagingAttemptInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingAttemptInformationAPERValueFieldReplay(v *PagingAttemptInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingAttemptInformationAPERValueFieldWithoutReplay(v *PagingAttemptInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingAttemptInformationFieldExtCount(v *PagingAttemptInformation) *int64 {
	return &v.extCount
}
func BridgePagingAttemptInformationFieldExtData(v *PagingAttemptInformation) *[][]byte {
	return &v.extData
}
func BridgePagingAttemptInformationFieldExtOrigin(v *PagingAttemptInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePagingAttemptInformationFieldExtPresent(v *PagingAttemptInformation) *[]bool {
	return &v.extPresent
}
func BridgePagingAttemptInformationFieldExtWire(v *PagingAttemptInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePagingAttemptInformationFieldIEExtensionsIndef(v *PagingAttemptInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgePagingAttemptInformationFieldPerExtPadding(v *PagingAttemptInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePagingAttemptInformationFieldPerPadding(v *PagingAttemptInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePagingAttemptInformationFieldReceived(v *PagingAttemptInformation) *bool {
	return &v.received
}
func BridgePagingAttemptInformationFieldReceivedAbsolute(v *PagingAttemptInformation) *bool {
	return &v.receivedAbsolute
}
func BridgePagingAttemptInformationFieldReceivedBytes(v *PagingAttemptInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePagingAttemptInformationFieldReceivedLocation(v *PagingAttemptInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgePagingAttemptInformationFieldReplay(v *PagingAttemptInformation) *aper.Snapshot {
	return &v.replay
}
func BridgePagingAttemptInformationFieldStream(v *PagingAttemptInformation) *aper.WireSpan {
	return &v.stream
}
func BridgePagingAttemptInformationFieldWithoutReplay(v *PagingAttemptInformation) *bool {
	return &v.withoutReplay
}
func BridgePagingAttemptInformationMethodMarshalAPERBudget(v *PagingAttemptInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePagingAttemptInformationMethodMarshalAPERBudgetValue(v *PagingAttemptInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePagingAttemptInformationMethodMarshalAPERChanged(v *PagingAttemptInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePagingAttemptInformationMethodMarshalAPERChangedValue(v *PagingAttemptInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePagingAttemptInformationMethodMarshalAPERLegacy(v *PagingAttemptInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePagingAttemptInformationMethodMarshalAPERNewValue(v *PagingAttemptInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePagingAttemptInformationMethodMarshalAPERPlanned(v *PagingAttemptInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePagingAttemptInformationMethodMarshalAPERTo(v *PagingAttemptInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingAttemptInformationMethodUnmarshalAPERFrom(v *PagingAttemptInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingAttemptInformationMethodUnmarshalAPERLegacy(v *PagingAttemptInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePagingAttemptInformationMethodUnmarshalAPERWithOptions(v *PagingAttemptInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePagingAttemptInformationValueCodecFieldCapture(v *PagingAttemptInformationValueCodec) *func(PagingAttemptInformation, aper.DecodeState) (PagingAttemptInformation, aper.Snapshot) {
	return &v.capture
}
func BridgePagingAttemptInformationValueCodecFieldCompare(v *PagingAttemptInformationValueCodec) *func(PagingAttemptInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingAttemptInformationValueCodecFieldContext(v *PagingAttemptInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingAttemptInformationValueCodecFieldDecode(v *PagingAttemptInformationValueCodec) *func([]byte, aper.DecodeState) (PagingAttemptInformation, error) {
	return &v.decode
}
func BridgePagingAttemptInformationValueCodecFieldEncode(v *PagingAttemptInformationValueCodec) *func(PagingAttemptInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingAttemptInformationValueCodecFieldPath(v *PagingAttemptInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingAttemptInformationValueCodecMethodEncodeBudgetValue(v PagingAttemptInformationValueCodec, a0 PagingAttemptInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingAttemptInformationValueCodecMethodEncodeChanged(v PagingAttemptInformationValueCodec, a0 PagingAttemptInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePagingEDRXInformationAPERValueFieldContext(v *PagingEDRXInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingEDRXInformationAPERValueFieldReceived(v *PagingEDRXInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePagingEDRXInformationAPERValueFieldReplay(v *PagingEDRXInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePagingEDRXInformationAPERValueFieldWithoutReplay(v *PagingEDRXInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePagingEDRXInformationFieldExtCount(v *PagingEDRXInformation) *int64   { return &v.extCount }
func BridgePagingEDRXInformationFieldExtData(v *PagingEDRXInformation) *[][]byte { return &v.extData }
func BridgePagingEDRXInformationFieldExtOrigin(v *PagingEDRXInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePagingEDRXInformationFieldExtPresent(v *PagingEDRXInformation) *[]bool {
	return &v.extPresent
}
func BridgePagingEDRXInformationFieldExtWire(v *PagingEDRXInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePagingEDRXInformationFieldIEExtensionsIndef(v *PagingEDRXInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgePagingEDRXInformationFieldPerExtPadding(v *PagingEDRXInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePagingEDRXInformationFieldPerPadding(v *PagingEDRXInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePagingEDRXInformationFieldReceived(v *PagingEDRXInformation) *bool { return &v.received }
func BridgePagingEDRXInformationFieldReceivedAbsolute(v *PagingEDRXInformation) *bool {
	return &v.receivedAbsolute
}
func BridgePagingEDRXInformationFieldReceivedBytes(v *PagingEDRXInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePagingEDRXInformationFieldReceivedLocation(v *PagingEDRXInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgePagingEDRXInformationFieldReplay(v *PagingEDRXInformation) *aper.Snapshot {
	return &v.replay
}
func BridgePagingEDRXInformationFieldStream(v *PagingEDRXInformation) *aper.WireSpan {
	return &v.stream
}
func BridgePagingEDRXInformationFieldWithoutReplay(v *PagingEDRXInformation) *bool {
	return &v.withoutReplay
}
func BridgePagingEDRXInformationMethodMarshalAPERBudget(v *PagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePagingEDRXInformationMethodMarshalAPERBudgetValue(v *PagingEDRXInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePagingEDRXInformationMethodMarshalAPERChanged(v *PagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePagingEDRXInformationMethodMarshalAPERChangedValue(v *PagingEDRXInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePagingEDRXInformationMethodMarshalAPERLegacy(v *PagingEDRXInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePagingEDRXInformationMethodMarshalAPERNewValue(v *PagingEDRXInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePagingEDRXInformationMethodMarshalAPERPlanned(v *PagingEDRXInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePagingEDRXInformationMethodMarshalAPERTo(v *PagingEDRXInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePagingEDRXInformationMethodUnmarshalAPERFrom(v *PagingEDRXInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingEDRXInformationMethodUnmarshalAPERLegacy(v *PagingEDRXInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePagingEDRXInformationMethodUnmarshalAPERWithOptions(v *PagingEDRXInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePagingEDRXInformationValueCodecFieldCapture(v *PagingEDRXInformationValueCodec) *func(PagingEDRXInformation, aper.DecodeState) (PagingEDRXInformation, aper.Snapshot) {
	return &v.capture
}
func BridgePagingEDRXInformationValueCodecFieldCompare(v *PagingEDRXInformationValueCodec) *func(PagingEDRXInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingEDRXInformationValueCodecFieldContext(v *PagingEDRXInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingEDRXInformationValueCodecFieldDecode(v *PagingEDRXInformationValueCodec) *func([]byte, aper.DecodeState) (PagingEDRXInformation, error) {
	return &v.decode
}
func BridgePagingEDRXInformationValueCodecFieldEncode(v *PagingEDRXInformationValueCodec) *func(PagingEDRXInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingEDRXInformationValueCodecFieldPath(v *PagingEDRXInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingEDRXInformationValueCodecMethodEncodeBudgetValue(v PagingEDRXInformationValueCodec, a0 PagingEDRXInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePagingEDRXInformationValueCodecMethodEncodeChanged(v PagingEDRXInformationValueCodec, a0 PagingEDRXInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateIEIDAPERValueFieldContext(v *PrivateIEIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDAPERValueFieldReceived(v *PrivateIEIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateIEIDAPERValueFieldReplay(v *PrivateIEIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgePrivateIEIDAPERValueFieldWithoutReplay(v *PrivateIEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateIEIDFieldPerOpenTypePadding(v *PrivateIEID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgePrivateIEIDFieldPerPadding(v *PrivateIEID) *aper.CompletePadding { return &v.perPadding }
func BridgePrivateIEIDFieldReceived(v *PrivateIEID) *bool                   { return &v.received }
func BridgePrivateIEIDFieldReceivedAbsolute(v *PrivateIEID) *bool           { return &v.receivedAbsolute }
func BridgePrivateIEIDFieldReceivedBytes(v *PrivateIEID) *aper.WireSpan     { return &v.receivedBytes }
func BridgePrivateIEIDFieldReceivedLocation(v *PrivateIEID) *aper.Location {
	return &v.receivedLocation
}
func BridgePrivateIEIDFieldReplay(v *PrivateIEID) *aper.Snapshot { return &v.replay }
func BridgePrivateIEIDFieldStream(v *PrivateIEID) *aper.WireSpan { return &v.stream }
func BridgePrivateIEIDFieldWithoutReplay(v *PrivateIEID) *bool   { return &v.withoutReplay }
func BridgePrivateIEIDMethodMarshalAPERBudget(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERBudgetValue(v *PrivateIEID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERChanged(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERChangedValue(v *PrivateIEID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERLegacy(v *PrivateIEID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateIEIDMethodMarshalAPERNewValue(v *PrivateIEID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERPlanned(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERTo(v *PrivateIEID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateIEIDMethodUnmarshalAPERFrom(v *PrivateIEID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERLegacy(v *PrivateIEID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERWithOptions(v *PrivateIEID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateIEIDValueCodecFieldCapture(v *PrivateIEIDValueCodec) *func(PrivateIEID, aper.DecodeState) (PrivateIEID, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateIEIDValueCodecFieldCompare(v *PrivateIEIDValueCodec) *func(PrivateIEID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivateIEIDValueCodecFieldContext(v *PrivateIEIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDValueCodecFieldDecode(v *PrivateIEIDValueCodec) *func([]byte, aper.DecodeState) (PrivateIEID, error) {
	return &v.decode
}
func BridgePrivateIEIDValueCodecFieldEncode(v *PrivateIEIDValueCodec) *func(PrivateIEID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateIEIDValueCodecFieldPath(v *PrivateIEIDValueCodec) *aper.Path { return &v.path }
func BridgePrivateIEIDValueCodecMethodEncodeBudgetValue(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePrivateIEIDValueCodecMethodEncodeChanged(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeProSeAuthorizedAPERValueFieldContext(v *ProSeAuthorizedAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeAuthorizedAPERValueFieldReceived(v *ProSeAuthorizedAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeProSeAuthorizedAPERValueFieldReplay(v *ProSeAuthorizedAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeProSeAuthorizedAPERValueFieldWithoutReplay(v *ProSeAuthorizedAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeProSeAuthorizedFieldExtCount(v *ProSeAuthorized) *int64   { return &v.extCount }
func BridgeProSeAuthorizedFieldExtData(v *ProSeAuthorized) *[][]byte { return &v.extData }
func BridgeProSeAuthorizedFieldExtOrigin(v *ProSeAuthorized) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeProSeAuthorizedFieldExtPresent(v *ProSeAuthorized) *[]bool       { return &v.extPresent }
func BridgeProSeAuthorizedFieldExtWire(v *ProSeAuthorized) *[]aper.WireSpan { return &v.extWire }
func BridgeProSeAuthorizedFieldIEExtensionsIndef(v *ProSeAuthorized) *bool {
	return &v.iEExtensionsIndef
}
func BridgeProSeAuthorizedFieldPerExtPadding(v *ProSeAuthorized) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeProSeAuthorizedFieldPerPadding(v *ProSeAuthorized) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeProSeAuthorizedFieldReceived(v *ProSeAuthorized) *bool         { return &v.received }
func BridgeProSeAuthorizedFieldReceivedAbsolute(v *ProSeAuthorized) *bool { return &v.receivedAbsolute }
func BridgeProSeAuthorizedFieldReceivedBytes(v *ProSeAuthorized) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeProSeAuthorizedFieldReceivedLocation(v *ProSeAuthorized) *aper.Location {
	return &v.receivedLocation
}
func BridgeProSeAuthorizedFieldReplay(v *ProSeAuthorized) *aper.Snapshot { return &v.replay }
func BridgeProSeAuthorizedFieldStream(v *ProSeAuthorized) *aper.WireSpan { return &v.stream }
func BridgeProSeAuthorizedFieldWithoutReplay(v *ProSeAuthorized) *bool   { return &v.withoutReplay }
func BridgeProSeAuthorizedMethodMarshalAPERBudget(v *ProSeAuthorized, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeProSeAuthorizedMethodMarshalAPERBudgetValue(v *ProSeAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeProSeAuthorizedMethodMarshalAPERChanged(v *ProSeAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeProSeAuthorizedMethodMarshalAPERChangedValue(v *ProSeAuthorized, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeProSeAuthorizedMethodMarshalAPERLegacy(v *ProSeAuthorized) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeProSeAuthorizedMethodMarshalAPERNewValue(v *ProSeAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeProSeAuthorizedMethodMarshalAPERPlanned(v *ProSeAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeProSeAuthorizedMethodMarshalAPERTo(v *ProSeAuthorized, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeProSeAuthorizedMethodUnmarshalAPERFrom(v *ProSeAuthorized, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeProSeAuthorizedMethodUnmarshalAPERLegacy(v *ProSeAuthorized, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeProSeAuthorizedMethodUnmarshalAPERWithOptions(v *ProSeAuthorized, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeProSeAuthorizedValueCodecFieldCapture(v *ProSeAuthorizedValueCodec) *func(ProSeAuthorized, aper.DecodeState) (ProSeAuthorized, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeAuthorizedValueCodecFieldCompare(v *ProSeAuthorizedValueCodec) *func(ProSeAuthorized, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeAuthorizedValueCodecFieldContext(v *ProSeAuthorizedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeAuthorizedValueCodecFieldDecode(v *ProSeAuthorizedValueCodec) *func([]byte, aper.DecodeState) (ProSeAuthorized, error) {
	return &v.decode
}
func BridgeProSeAuthorizedValueCodecFieldEncode(v *ProSeAuthorizedValueCodec) *func(ProSeAuthorized, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeAuthorizedValueCodecFieldPath(v *ProSeAuthorizedValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeAuthorizedValueCodecMethodEncodeBudgetValue(v ProSeAuthorizedValueCodec, a0 ProSeAuthorized, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeProSeAuthorizedValueCodecMethodEncodeChanged(v ProSeAuthorizedValueCodec, a0 ProSeAuthorized, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRATRestrictionsAPERValueFieldContext(v *RATRestrictionsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsAPERValueFieldReceived(v *RATRestrictionsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRATRestrictionsAPERValueFieldReplay(v *RATRestrictionsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRATRestrictionsAPERValueFieldWithoutReplay(v *RATRestrictionsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRATRestrictionsItemAPERValueFieldContext(v *RATRestrictionsItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsItemAPERValueFieldReceived(v *RATRestrictionsItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRATRestrictionsItemAPERValueFieldReplay(v *RATRestrictionsItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRATRestrictionsItemAPERValueFieldWithoutReplay(v *RATRestrictionsItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRATRestrictionsItemFieldExtCount(v *RATRestrictionsItem) *int64   { return &v.extCount }
func BridgeRATRestrictionsItemFieldExtData(v *RATRestrictionsItem) *[][]byte { return &v.extData }
func BridgeRATRestrictionsItemFieldExtOrigin(v *RATRestrictionsItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRATRestrictionsItemFieldExtPresent(v *RATRestrictionsItem) *[]bool { return &v.extPresent }
func BridgeRATRestrictionsItemFieldExtWire(v *RATRestrictionsItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRATRestrictionsItemFieldIEExtensionsIndef(v *RATRestrictionsItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRATRestrictionsItemFieldPerExtPadding(v *RATRestrictionsItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRATRestrictionsItemFieldPerPadding(v *RATRestrictionsItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRATRestrictionsItemFieldReceived(v *RATRestrictionsItem) *bool { return &v.received }
func BridgeRATRestrictionsItemFieldReceivedAbsolute(v *RATRestrictionsItem) *bool {
	return &v.receivedAbsolute
}
func BridgeRATRestrictionsItemFieldReceivedBytes(v *RATRestrictionsItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRATRestrictionsItemFieldReceivedLocation(v *RATRestrictionsItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeRATRestrictionsItemFieldReplay(v *RATRestrictionsItem) *aper.Snapshot { return &v.replay }
func BridgeRATRestrictionsItemFieldStream(v *RATRestrictionsItem) *aper.WireSpan { return &v.stream }
func BridgeRATRestrictionsItemFieldWithoutReplay(v *RATRestrictionsItem) *bool {
	return &v.withoutReplay
}
func BridgeRATRestrictionsItemMethodMarshalAPERBudget(v *RATRestrictionsItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRATRestrictionsItemMethodMarshalAPERBudgetValue(v *RATRestrictionsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRATRestrictionsItemMethodMarshalAPERChanged(v *RATRestrictionsItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRATRestrictionsItemMethodMarshalAPERChangedValue(v *RATRestrictionsItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRATRestrictionsItemMethodMarshalAPERLegacy(v *RATRestrictionsItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRATRestrictionsItemMethodMarshalAPERNewValue(v *RATRestrictionsItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRATRestrictionsItemMethodMarshalAPERPlanned(v *RATRestrictionsItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRATRestrictionsItemMethodMarshalAPERTo(v *RATRestrictionsItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRATRestrictionsItemMethodUnmarshalAPERFrom(v *RATRestrictionsItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRATRestrictionsItemMethodUnmarshalAPERLegacy(v *RATRestrictionsItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRATRestrictionsItemMethodUnmarshalAPERWithOptions(v *RATRestrictionsItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRATRestrictionsItemValueCodecFieldCapture(v *RATRestrictionsItemValueCodec) *func(RATRestrictionsItem, aper.DecodeState) (RATRestrictionsItem, aper.Snapshot) {
	return &v.capture
}
func BridgeRATRestrictionsItemValueCodecFieldCompare(v *RATRestrictionsItemValueCodec) *func(RATRestrictionsItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRATRestrictionsItemValueCodecFieldContext(v *RATRestrictionsItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsItemValueCodecFieldDecode(v *RATRestrictionsItemValueCodec) *func([]byte, aper.DecodeState) (RATRestrictionsItem, error) {
	return &v.decode
}
func BridgeRATRestrictionsItemValueCodecFieldEncode(v *RATRestrictionsItemValueCodec) *func(RATRestrictionsItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRATRestrictionsItemValueCodecFieldPath(v *RATRestrictionsItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeRATRestrictionsItemValueCodecMethodEncodeBudgetValue(v RATRestrictionsItemValueCodec, a0 RATRestrictionsItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRATRestrictionsItemValueCodecMethodEncodeChanged(v RATRestrictionsItemValueCodec, a0 RATRestrictionsItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRATRestrictionsValueCodecFieldCapture(v *RATRestrictionsValueCodec) *func(RATRestrictions, aper.DecodeState) (RATRestrictions, aper.Snapshot) {
	return &v.capture
}
func BridgeRATRestrictionsValueCodecFieldCompare(v *RATRestrictionsValueCodec) *func(RATRestrictions, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRATRestrictionsValueCodecFieldContext(v *RATRestrictionsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATRestrictionsValueCodecFieldDecode(v *RATRestrictionsValueCodec) *func([]byte, aper.DecodeState) (RATRestrictions, error) {
	return &v.decode
}
func BridgeRATRestrictionsValueCodecFieldEncode(v *RATRestrictionsValueCodec) *func(RATRestrictions, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRATRestrictionsValueCodecFieldPath(v *RATRestrictionsValueCodec) *aper.Path {
	return &v.path
}
func BridgeRATRestrictionsValueCodecMethodEncodeBudgetValue(v RATRestrictionsValueCodec, a0 RATRestrictions, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRATRestrictionsValueCodecMethodEncodeChanged(v RATRestrictionsValueCodec, a0 RATRestrictions, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRLFReportInformationAPERValueFieldContext(v *RLFReportInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRLFReportInformationAPERValueFieldReceived(v *RLFReportInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRLFReportInformationAPERValueFieldReplay(v *RLFReportInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRLFReportInformationAPERValueFieldWithoutReplay(v *RLFReportInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRLFReportInformationFieldExtCount(v *RLFReportInformation) *int64   { return &v.extCount }
func BridgeRLFReportInformationFieldExtData(v *RLFReportInformation) *[][]byte { return &v.extData }
func BridgeRLFReportInformationFieldExtOrigin(v *RLFReportInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRLFReportInformationFieldExtPresent(v *RLFReportInformation) *[]bool { return &v.extPresent }
func BridgeRLFReportInformationFieldExtWire(v *RLFReportInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRLFReportInformationFieldIEExtensionsIndef(v *RLFReportInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRLFReportInformationFieldPerExtPadding(v *RLFReportInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRLFReportInformationFieldPerPadding(v *RLFReportInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRLFReportInformationFieldReceived(v *RLFReportInformation) *bool { return &v.received }
func BridgeRLFReportInformationFieldReceivedAbsolute(v *RLFReportInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeRLFReportInformationFieldReceivedBytes(v *RLFReportInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRLFReportInformationFieldReceivedLocation(v *RLFReportInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeRLFReportInformationFieldReplay(v *RLFReportInformation) *aper.Snapshot { return &v.replay }
func BridgeRLFReportInformationFieldStream(v *RLFReportInformation) *aper.WireSpan { return &v.stream }
func BridgeRLFReportInformationFieldWithoutReplay(v *RLFReportInformation) *bool {
	return &v.withoutReplay
}
func BridgeRLFReportInformationMethodMarshalAPERBudget(v *RLFReportInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRLFReportInformationMethodMarshalAPERBudgetValue(v *RLFReportInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRLFReportInformationMethodMarshalAPERChanged(v *RLFReportInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRLFReportInformationMethodMarshalAPERChangedValue(v *RLFReportInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRLFReportInformationMethodMarshalAPERLegacy(v *RLFReportInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRLFReportInformationMethodMarshalAPERNewValue(v *RLFReportInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRLFReportInformationMethodMarshalAPERPlanned(v *RLFReportInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRLFReportInformationMethodMarshalAPERTo(v *RLFReportInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRLFReportInformationMethodUnmarshalAPERFrom(v *RLFReportInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRLFReportInformationMethodUnmarshalAPERLegacy(v *RLFReportInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRLFReportInformationMethodUnmarshalAPERWithOptions(v *RLFReportInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRLFReportInformationValueCodecFieldCapture(v *RLFReportInformationValueCodec) *func(RLFReportInformation, aper.DecodeState) (RLFReportInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeRLFReportInformationValueCodecFieldCompare(v *RLFReportInformationValueCodec) *func(RLFReportInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRLFReportInformationValueCodecFieldContext(v *RLFReportInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRLFReportInformationValueCodecFieldDecode(v *RLFReportInformationValueCodec) *func([]byte, aper.DecodeState) (RLFReportInformation, error) {
	return &v.decode
}
func BridgeRLFReportInformationValueCodecFieldEncode(v *RLFReportInformationValueCodec) *func(RLFReportInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRLFReportInformationValueCodecFieldPath(v *RLFReportInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeRLFReportInformationValueCodecMethodEncodeBudgetValue(v RLFReportInformationValueCodec, a0 RLFReportInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRLFReportInformationValueCodecMethodEncodeChanged(v RLFReportInformationValueCodec, a0 RLFReportInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeReportingCellListAPERValueFieldContext(v *ReportingCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportingCellListAPERValueFieldReceived(v *ReportingCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeReportingCellListAPERValueFieldReplay(v *ReportingCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeReportingCellListAPERValueFieldWithoutReplay(v *ReportingCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeReportingCellListItemAPERValueFieldContext(v *ReportingCellListItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportingCellListItemAPERValueFieldReceived(v *ReportingCellListItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeReportingCellListItemAPERValueFieldReplay(v *ReportingCellListItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeReportingCellListItemAPERValueFieldWithoutReplay(v *ReportingCellListItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeReportingCellListItemFieldExtCount(v *ReportingCellListItem) *int64   { return &v.extCount }
func BridgeReportingCellListItemFieldExtData(v *ReportingCellListItem) *[][]byte { return &v.extData }
func BridgeReportingCellListItemFieldExtOrigin(v *ReportingCellListItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeReportingCellListItemFieldExtPresent(v *ReportingCellListItem) *[]bool {
	return &v.extPresent
}
func BridgeReportingCellListItemFieldExtWire(v *ReportingCellListItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeReportingCellListItemFieldPerExtPadding(v *ReportingCellListItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeReportingCellListItemFieldPerPadding(v *ReportingCellListItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeReportingCellListItemFieldReceived(v *ReportingCellListItem) *bool { return &v.received }
func BridgeReportingCellListItemFieldReceivedAbsolute(v *ReportingCellListItem) *bool {
	return &v.receivedAbsolute
}
func BridgeReportingCellListItemFieldReceivedBytes(v *ReportingCellListItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeReportingCellListItemFieldReceivedLocation(v *ReportingCellListItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeReportingCellListItemFieldReplay(v *ReportingCellListItem) *aper.Snapshot {
	return &v.replay
}
func BridgeReportingCellListItemFieldStream(v *ReportingCellListItem) *aper.WireSpan {
	return &v.stream
}
func BridgeReportingCellListItemFieldWithoutReplay(v *ReportingCellListItem) *bool {
	return &v.withoutReplay
}
func BridgeReportingCellListItemMethodMarshalAPERBudget(v *ReportingCellListItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeReportingCellListItemMethodMarshalAPERBudgetValue(v *ReportingCellListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeReportingCellListItemMethodMarshalAPERChanged(v *ReportingCellListItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeReportingCellListItemMethodMarshalAPERChangedValue(v *ReportingCellListItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeReportingCellListItemMethodMarshalAPERLegacy(v *ReportingCellListItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeReportingCellListItemMethodMarshalAPERNewValue(v *ReportingCellListItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeReportingCellListItemMethodMarshalAPERPlanned(v *ReportingCellListItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeReportingCellListItemMethodMarshalAPERTo(v *ReportingCellListItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeReportingCellListItemMethodUnmarshalAPERFrom(v *ReportingCellListItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeReportingCellListItemMethodUnmarshalAPERLegacy(v *ReportingCellListItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeReportingCellListItemMethodUnmarshalAPERWithOptions(v *ReportingCellListItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeReportingCellListItemValueCodecFieldCapture(v *ReportingCellListItemValueCodec) *func(ReportingCellListItem, aper.DecodeState) (ReportingCellListItem, aper.Snapshot) {
	return &v.capture
}
func BridgeReportingCellListItemValueCodecFieldCompare(v *ReportingCellListItemValueCodec) *func(ReportingCellListItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReportingCellListItemValueCodecFieldContext(v *ReportingCellListItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportingCellListItemValueCodecFieldDecode(v *ReportingCellListItemValueCodec) *func([]byte, aper.DecodeState) (ReportingCellListItem, error) {
	return &v.decode
}
func BridgeReportingCellListItemValueCodecFieldEncode(v *ReportingCellListItemValueCodec) *func(ReportingCellListItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportingCellListItemValueCodecFieldPath(v *ReportingCellListItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeReportingCellListItemValueCodecMethodEncodeBudgetValue(v ReportingCellListItemValueCodec, a0 ReportingCellListItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeReportingCellListItemValueCodecMethodEncodeChanged(v ReportingCellListItemValueCodec, a0 ReportingCellListItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeReportingCellListValueCodecFieldCapture(v *ReportingCellListValueCodec) *func(ReportingCellList, aper.DecodeState) (ReportingCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeReportingCellListValueCodecFieldCompare(v *ReportingCellListValueCodec) *func(ReportingCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReportingCellListValueCodecFieldContext(v *ReportingCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportingCellListValueCodecFieldDecode(v *ReportingCellListValueCodec) *func([]byte, aper.DecodeState) (ReportingCellList, error) {
	return &v.decode
}
func BridgeReportingCellListValueCodecFieldEncode(v *ReportingCellListValueCodec) *func(ReportingCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportingCellListValueCodecFieldPath(v *ReportingCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeReportingCellListValueCodecMethodEncodeBudgetValue(v ReportingCellListValueCodec, a0 ReportingCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeReportingCellListValueCodecMethodEncodeChanged(v ReportingCellListValueCodec, a0 ReportingCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRequestedCellListAPERValueFieldContext(v *RequestedCellListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedCellListAPERValueFieldReceived(v *RequestedCellListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRequestedCellListAPERValueFieldReplay(v *RequestedCellListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestedCellListAPERValueFieldWithoutReplay(v *RequestedCellListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRequestedCellListValueCodecFieldCapture(v *RequestedCellListValueCodec) *func(RequestedCellList, aper.DecodeState) (RequestedCellList, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestedCellListValueCodecFieldCompare(v *RequestedCellListValueCodec) *func(RequestedCellList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestedCellListValueCodecFieldContext(v *RequestedCellListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedCellListValueCodecFieldDecode(v *RequestedCellListValueCodec) *func([]byte, aper.DecodeState) (RequestedCellList, error) {
	return &v.decode
}
func BridgeRequestedCellListValueCodecFieldEncode(v *RequestedCellListValueCodec) *func(RequestedCellList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedCellListValueCodecFieldPath(v *RequestedCellListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestedCellListValueCodecMethodEncodeBudgetValue(v RequestedCellListValueCodec, a0 RequestedCellList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRequestedCellListValueCodecMethodEncodeChanged(v RequestedCellListValueCodec, a0 RequestedCellList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldCodec(v *RerouteNASRequestAdditionalGUTIIEBinding) *s18.AdditionalGUTIValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldGet(v *RerouteNASRequestAdditionalGUTIIEBinding) *func(*RerouteNASRequestIEValue) (*s18.AdditionalGUTI, bool) {
	return &v.get
}
func BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldInfo(v *RerouteNASRequestAdditionalGUTIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestAdditionalGUTIIEBindingFieldInject(v *RerouteNASRequestAdditionalGUTIIEBinding) *func(s18.AdditionalGUTI) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeRerouteNASRequestENBUES1APIDIEBindingFieldCodec(v *RerouteNASRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestENBUES1APIDIEBindingFieldGet(v *RerouteNASRequestENBUES1APIDIEBinding) *func(*RerouteNASRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeRerouteNASRequestENBUES1APIDIEBindingFieldInfo(v *RerouteNASRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestENBUES1APIDIEBindingFieldInject(v *RerouteNASRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeRerouteNASRequestIEContainerAPERValueFieldContext(v *RerouteNASRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEContainerAPERValueFieldReceived(v *RerouteNASRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEContainerAPERValueFieldReplay(v *RerouteNASRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEContainerAPERValueFieldWithoutReplay(v *RerouteNASRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldCapture(v *RerouteNASRequestIEContainerValueCodec) *func(RerouteNASRequestIEContainer, aper.DecodeState) (RerouteNASRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldCompare(v *RerouteNASRequestIEContainerValueCodec) *func(RerouteNASRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldContext(v *RerouteNASRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldDecode(v *RerouteNASRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEContainer, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldEncode(v *RerouteNASRequestIEContainerValueCodec) *func(RerouteNASRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEContainerValueCodecFieldPath(v *RerouteNASRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEContainerValueCodecMethodEncodeBudgetValue(v RerouteNASRequestIEContainerValueCodec, a0 RerouteNASRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRerouteNASRequestIEContainerValueCodecMethodEncodeChanged(v RerouteNASRequestIEContainerValueCodec, a0 RerouteNASRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestIEFieldAPERValueFieldContext(v *RerouteNASRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEFieldAPERValueFieldReceived(v *RerouteNASRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEFieldAPERValueFieldReplay(v *RerouteNASRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEFieldAPERValueFieldWithoutReplay(v *RerouteNASRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEFieldFieldReceived(v *RerouteNASRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeRerouteNASRequestIEFieldFieldReplay(v *RerouteNASRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEFieldFieldStream(v *RerouteNASRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeRerouteNASRequestIEFieldFieldWithoutReplay(v *RerouteNASRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEFieldMethodMarshalAPERTo(v *RerouteNASRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRerouteNASRequestIEFieldMethodUnmarshalAPERFrom(v *RerouteNASRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldCapture(v *RerouteNASRequestIEFieldValueCodec) *func(RerouteNASRequestIEField, aper.DecodeState) (RerouteNASRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldCompare(v *RerouteNASRequestIEFieldValueCodec) *func(RerouteNASRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldContext(v *RerouteNASRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldDecode(v *RerouteNASRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEField, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldEncode(v *RerouteNASRequestIEFieldValueCodec) *func(RerouteNASRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEFieldValueCodecFieldPath(v *RerouteNASRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEFieldValueCodecMethodEncodeBudgetValue(v RerouteNASRequestIEFieldValueCodec, a0 RerouteNASRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRerouteNASRequestIEFieldValueCodecMethodEncodeChanged(v RerouteNASRequestIEFieldValueCodec, a0 RerouteNASRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestIETableMethodInfoAdditionalGUTI(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoAdditionalGUTI()
}
func BridgeRerouteNASRequestIETableMethodInfoENBUES1APID(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeRerouteNASRequestIETableMethodInfoMMEGroupID(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoMMEGroupID()
}
func BridgeRerouteNASRequestIETableMethodInfoMMEUES1APID(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeRerouteNASRequestIETableMethodInfoS1Message(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoS1Message()
}
func BridgeRerouteNASRequestIETableMethodInfoUEUsageType(v RerouteNASRequestIETable) s00.FieldInfo {
	return v.infoUEUsageType()
}
func BridgeRerouteNASRequestIEValueERABIEContainerListAPERValueFieldContext(v *RerouteNASRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueERABIEContainerListAPERValueFieldReceived(v *RerouteNASRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEValueERABIEContainerListAPERValueFieldReplay(v *RerouteNASRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *RerouteNASRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *func(RerouteNASRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v RerouteNASRequestIEValueERABIEContainerListValueCodec, a0 RerouteNASRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRerouteNASRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v RerouteNASRequestIEValueERABIEContainerListValueCodec, a0 RerouteNASRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestIEValueFieldId(v *RerouteNASRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeRerouteNASRequestIEValueFieldIsOpaque(v *RerouteNASRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeRerouteNASRequestIEValueFieldOpaque(v *RerouteNASRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeRerouteNASRequestIEValueFieldReceived(v *RerouteNASRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEValueFieldReplay(v *RerouteNASRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEValueFieldRowAdditionalGUTI(v *RerouteNASRequestIEValue) **s18.AdditionalGUTI {
	return &v.rowAdditionalGUTI
}
func BridgeRerouteNASRequestIEValueFieldRowENBUES1APID(v *RerouteNASRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeRerouteNASRequestIEValueFieldRowMMEGroupID(v *RerouteNASRequestIEValue) **s00.MMEGroupID {
	return &v.rowMMEGroupID
}
func BridgeRerouteNASRequestIEValueFieldRowMMEUES1APID(v *RerouteNASRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeRerouteNASRequestIEValueFieldRowS1Message(v *RerouteNASRequestIEValue) **[]byte {
	return &v.rowS1Message
}
func BridgeRerouteNASRequestIEValueFieldRowUEUsageType(v *RerouteNASRequestIEValue) **s00.UEUsageType {
	return &v.rowUEUsageType
}
func BridgeRerouteNASRequestIEValueMethodCaptureSemantics(v RerouteNASRequestIEValue, a0 aper.SemanticCapture) RerouteNASRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeRerouteNASRequestIEValueMethodCompareSemantics(v RerouteNASRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeRerouteNASRequestIEValueMethodDecode(v RerouteNASRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (RerouteNASRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeRerouteNASRequestIEValueMethodEncode(v RerouteNASRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeRerouteNASRequestIEValueMethodEncodeFresh(v RerouteNASRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeRerouteNASRequestIEValueMethodMatchesID(v RerouteNASRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeRerouteNASRequestIEValueMethodReason(v RerouteNASRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeRerouteNASRequestIEValueMethodRule(v RerouteNASRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *RerouteNASRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec, a0 RerouteNASRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRerouteNASRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v RerouteNASRequestIEValueProtocolErrorIEContainerListValueCodec, a0 RerouteNASRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *RerouteNASRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *RerouteNASRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *RerouteNASRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *RerouteNASRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (RerouteNASRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *func(RerouteNASRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *RerouteNASRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v RerouteNASRequestIEValueProtocolIEContainerListValueCodec, a0 RerouteNASRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRerouteNASRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v RerouteNASRequestIEValueProtocolIEContainerListValueCodec, a0 RerouteNASRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRerouteNASRequestMMEGroupIDIEBindingFieldCodec(v *RerouteNASRequestMMEGroupIDIEBinding) *s01.MMEGroupIDValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestMMEGroupIDIEBindingFieldGet(v *RerouteNASRequestMMEGroupIDIEBinding) *func(*RerouteNASRequestIEValue) (*s00.MMEGroupID, bool) {
	return &v.get
}
func BridgeRerouteNASRequestMMEGroupIDIEBindingFieldInfo(v *RerouteNASRequestMMEGroupIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestMMEGroupIDIEBindingFieldInject(v *RerouteNASRequestMMEGroupIDIEBinding) *func(s00.MMEGroupID) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeRerouteNASRequestMMEUES1APIDIEBindingFieldCodec(v *RerouteNASRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestMMEUES1APIDIEBindingFieldGet(v *RerouteNASRequestMMEUES1APIDIEBinding) *func(*RerouteNASRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeRerouteNASRequestMMEUES1APIDIEBindingFieldInfo(v *RerouteNASRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestMMEUES1APIDIEBindingFieldInject(v *RerouteNASRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeRerouteNASRequestSliceByteIEBindingFieldCodec(v *RerouteNASRequestSliceByteIEBinding) *s01.SliceByteValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestSliceByteIEBindingFieldGet(v *RerouteNASRequestSliceByteIEBinding) *func(*RerouteNASRequestIEValue) (*[]byte, bool) {
	return &v.get
}
func BridgeRerouteNASRequestSliceByteIEBindingFieldInfo(v *RerouteNASRequestSliceByteIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestSliceByteIEBindingFieldInject(v *RerouteNASRequestSliceByteIEBinding) *func([]byte) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeRerouteNASRequestUEUsageTypeIEBindingFieldCodec(v *RerouteNASRequestUEUsageTypeIEBinding) *s02.UEUsageTypeValueCodec {
	return &v.codec
}
func BridgeRerouteNASRequestUEUsageTypeIEBindingFieldGet(v *RerouteNASRequestUEUsageTypeIEBinding) *func(*RerouteNASRequestIEValue) (*s00.UEUsageType, bool) {
	return &v.get
}
func BridgeRerouteNASRequestUEUsageTypeIEBindingFieldInfo(v *RerouteNASRequestUEUsageTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeRerouteNASRequestUEUsageTypeIEBindingFieldInject(v *RerouteNASRequestUEUsageTypeIEBinding) *func(s00.UEUsageType) RerouteNASRequestIEValue {
	return &v.inject
}
func BridgeS1RemovalRequestGlobalENBIDIEBindingFieldCodec(v *S1RemovalRequestGlobalENBIDIEBinding) *s18.GlobalENBIDValueCodec {
	return &v.codec
}
func BridgeS1RemovalRequestGlobalENBIDIEBindingFieldGet(v *S1RemovalRequestGlobalENBIDIEBinding) *func(*S1RemovalRequestIEValue) (*s18.GlobalENBID, bool) {
	return &v.get
}
func BridgeS1RemovalRequestGlobalENBIDIEBindingFieldInfo(v *S1RemovalRequestGlobalENBIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeS1RemovalRequestGlobalENBIDIEBindingFieldInject(v *S1RemovalRequestGlobalENBIDIEBinding) *func(s18.GlobalENBID) S1RemovalRequestIEValue {
	return &v.inject
}
func BridgeS1RemovalRequestIEContainerAPERValueFieldContext(v *S1RemovalRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEContainerAPERValueFieldReceived(v *S1RemovalRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEContainerAPERValueFieldReplay(v *S1RemovalRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEContainerAPERValueFieldWithoutReplay(v *S1RemovalRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldCapture(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, aper.DecodeState) (S1RemovalRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldCompare(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldContext(v *S1RemovalRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldDecode(v *S1RemovalRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEContainer, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldEncode(v *S1RemovalRequestIEContainerValueCodec) *func(S1RemovalRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEContainerValueCodecFieldPath(v *S1RemovalRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEContainerValueCodecMethodEncodeBudgetValue(v S1RemovalRequestIEContainerValueCodec, a0 S1RemovalRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalRequestIEContainerValueCodecMethodEncodeChanged(v S1RemovalRequestIEContainerValueCodec, a0 S1RemovalRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalRequestIEFieldAPERValueFieldContext(v *S1RemovalRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEFieldAPERValueFieldReceived(v *S1RemovalRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEFieldAPERValueFieldReplay(v *S1RemovalRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEFieldAPERValueFieldWithoutReplay(v *S1RemovalRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEFieldFieldReceived(v *S1RemovalRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeS1RemovalRequestIEFieldFieldReplay(v *S1RemovalRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEFieldFieldStream(v *S1RemovalRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeS1RemovalRequestIEFieldFieldWithoutReplay(v *S1RemovalRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEFieldMethodMarshalAPERTo(v *S1RemovalRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1RemovalRequestIEFieldMethodUnmarshalAPERFrom(v *S1RemovalRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldCapture(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, aper.DecodeState) (S1RemovalRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldCompare(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldContext(v *S1RemovalRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldDecode(v *S1RemovalRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEField, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldEncode(v *S1RemovalRequestIEFieldValueCodec) *func(S1RemovalRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEFieldValueCodecFieldPath(v *S1RemovalRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEFieldValueCodecMethodEncodeBudgetValue(v S1RemovalRequestIEFieldValueCodec, a0 S1RemovalRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalRequestIEFieldValueCodecMethodEncodeChanged(v S1RemovalRequestIEFieldValueCodec, a0 S1RemovalRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalRequestIETableMethodInfoGlobalENBID(v S1RemovalRequestIETable) s00.FieldInfo {
	return v.infoGlobalENBID()
}
func BridgeS1RemovalRequestIEValueERABIEContainerListAPERValueFieldContext(v *S1RemovalRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueERABIEContainerListAPERValueFieldReceived(v *S1RemovalRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEValueERABIEContainerListAPERValueFieldReplay(v *S1RemovalRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *func(S1RemovalRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalRequestIEValueERABIEContainerListValueCodec, a0 S1RemovalRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v S1RemovalRequestIEValueERABIEContainerListValueCodec, a0 S1RemovalRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalRequestIEValueFieldId(v *S1RemovalRequestIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeS1RemovalRequestIEValueFieldIsOpaque(v *S1RemovalRequestIEValue) *bool       { return &v.isOpaque }
func BridgeS1RemovalRequestIEValueFieldOpaque(v *S1RemovalRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeS1RemovalRequestIEValueFieldReceived(v *S1RemovalRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEValueFieldReplay(v *S1RemovalRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEValueFieldRowGlobalENBID(v *S1RemovalRequestIEValue) **s18.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgeS1RemovalRequestIEValueMethodCaptureSemantics(v S1RemovalRequestIEValue, a0 aper.SemanticCapture) S1RemovalRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeS1RemovalRequestIEValueMethodCompareSemantics(v S1RemovalRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeS1RemovalRequestIEValueMethodDecode(v S1RemovalRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (S1RemovalRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeS1RemovalRequestIEValueMethodEncode(v S1RemovalRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeS1RemovalRequestIEValueMethodEncodeFresh(v S1RemovalRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeS1RemovalRequestIEValueMethodMatchesID(v S1RemovalRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeS1RemovalRequestIEValueMethodReason(v S1RemovalRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeS1RemovalRequestIEValueMethodRule(v S1RemovalRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v S1RemovalRequestIEValueProtocolErrorIEContainerListValueCodec, a0 S1RemovalRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *S1RemovalRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *S1RemovalRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *S1RemovalRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *S1RemovalRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (S1RemovalRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *func(S1RemovalRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *S1RemovalRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v S1RemovalRequestIEValueProtocolIEContainerListValueCodec, a0 S1RemovalRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1RemovalRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v S1RemovalRequestIEValueProtocolIEContainerListValueCodec, a0 S1RemovalRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionAPERValueFieldContext(v *SONInformationExtensionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionAPERValueFieldReceived(v *SONInformationExtensionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionAPERValueFieldReplay(v *SONInformationExtensionAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionAPERValueFieldWithoutReplay(v *SONInformationExtensionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionFieldPerPadding(v *SONInformationExtension) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONInformationExtensionFieldReceived(v *SONInformationExtension) *bool { return &v.received }
func BridgeSONInformationExtensionFieldReceivedAbsolute(v *SONInformationExtension) *bool {
	return &v.receivedAbsolute
}
func BridgeSONInformationExtensionFieldReceivedBytes(v *SONInformationExtension) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONInformationExtensionFieldReceivedLocation(v *SONInformationExtension) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONInformationExtensionFieldReplay(v *SONInformationExtension) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionFieldStream(v *SONInformationExtension) *aper.WireSpan {
	return &v.stream
}
func BridgeSONInformationExtensionFieldWithoutReplay(v *SONInformationExtension) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEContainerAPERValueFieldContext(v *SONInformationExtensionIEIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEContainerAPERValueFieldReceived(v *SONInformationExtensionIEIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEContainerAPERValueFieldReplay(v *SONInformationExtensionIEIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEContainerAPERValueFieldWithoutReplay(v *SONInformationExtensionIEIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldCapture(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, aper.DecodeState) (SONInformationExtensionIEIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldCompare(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldContext(v *SONInformationExtensionIEIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldDecode(v *SONInformationExtensionIEIEContainerValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEContainer, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldEncode(v *SONInformationExtensionIEIEContainerValueCodec) *func(SONInformationExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEContainerValueCodecFieldPath(v *SONInformationExtensionIEIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEContainerValueCodecMethodEncodeBudgetValue(v SONInformationExtensionIEIEContainerValueCodec, a0 SONInformationExtensionIEIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionIEIEContainerValueCodecMethodEncodeChanged(v SONInformationExtensionIEIEContainerValueCodec, a0 SONInformationExtensionIEIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionIEIEFieldAPERValueFieldContext(v *SONInformationExtensionIEIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEFieldAPERValueFieldReceived(v *SONInformationExtensionIEIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEFieldAPERValueFieldReplay(v *SONInformationExtensionIEIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEFieldAPERValueFieldWithoutReplay(v *SONInformationExtensionIEIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEFieldFieldReceived(v *SONInformationExtensionIEIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSONInformationExtensionIEIEFieldFieldReplay(v *SONInformationExtensionIEIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEFieldFieldStream(v *SONInformationExtensionIEIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSONInformationExtensionIEIEFieldFieldWithoutReplay(v *SONInformationExtensionIEIEField) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEFieldMethodMarshalAPERTo(v *SONInformationExtensionIEIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationExtensionIEIEFieldMethodUnmarshalAPERFrom(v *SONInformationExtensionIEIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldCapture(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, aper.DecodeState) (SONInformationExtensionIEIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldCompare(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldContext(v *SONInformationExtensionIEIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldDecode(v *SONInformationExtensionIEIEFieldValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEField, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldEncode(v *SONInformationExtensionIEIEFieldValueCodec) *func(SONInformationExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEFieldValueCodecFieldPath(v *SONInformationExtensionIEIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEFieldValueCodecMethodEncodeBudgetValue(v SONInformationExtensionIEIEFieldValueCodec, a0 SONInformationExtensionIEIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionIEIEFieldValueCodecMethodEncodeChanged(v SONInformationExtensionIEIEFieldValueCodec, a0 SONInformationExtensionIEIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListAPERValueFieldContext(v *SONInformationExtensionIEIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListAPERValueFieldReceived(v *SONInformationExtensionIEIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListAPERValueFieldReplay(v *SONInformationExtensionIEIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *SONInformationExtensionIEIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v SONInformationExtensionIEIEValueERABIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionIEIEValueERABIEContainerListValueCodecMethodEncodeChanged(v SONInformationExtensionIEIEValueERABIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionIEIEValueFieldId(v *SONInformationExtensionIEIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSONInformationExtensionIEIEValueFieldIsOpaque(v *SONInformationExtensionIEIEValue) *bool {
	return &v.isOpaque
}
func BridgeSONInformationExtensionIEIEValueFieldOpaque(v *SONInformationExtensionIEIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSONInformationExtensionIEIEValueFieldReceived(v *SONInformationExtensionIEIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEValueFieldReplay(v *SONInformationExtensionIEIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEValueFieldRowSONInformationReport(v *SONInformationExtensionIEIEValue) **SONInformationReport {
	return &v.rowSONInformationReport
}
func BridgeSONInformationExtensionIEIEValueMethodCaptureSemantics(v SONInformationExtensionIEIEValue, a0 aper.SemanticCapture) SONInformationExtensionIEIEValue {
	return v.captureSemantics(a0)
}
func BridgeSONInformationExtensionIEIEValueMethodCompareSemantics(v SONInformationExtensionIEIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSONInformationExtensionIEIEValueMethodDecode(v SONInformationExtensionIEIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SONInformationExtensionIEIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeSONInformationExtensionIEIEValueMethodEncode(v SONInformationExtensionIEIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeSONInformationExtensionIEIEValueMethodEncodeFresh(v SONInformationExtensionIEIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSONInformationExtensionIEIEValueMethodMatchesID(v SONInformationExtensionIEIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSONInformationExtensionIEIEValueMethodReason(v SONInformationExtensionIEIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSONInformationExtensionIEIEValueMethodRule(v SONInformationExtensionIEIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v SONInformationExtensionIEIEValueProtocolErrorIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListAPERValueFieldContext(v *SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListAPERValueFieldReceived(v *SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListAPERValueFieldReplay(v *SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *SONInformationExtensionIEIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtensionIEIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *func(SONInformationExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(v *SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionIEIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v SONInformationExtensionIEIEValueProtocolIEContainerListValueCodec, a0 SONInformationExtensionIEIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationExtensionIESONInformationReportIEBindingFieldCodec(v *SONInformationExtensionIESONInformationReportIEBinding) *SONInformationReportValueCodec {
	return &v.codec
}
func BridgeSONInformationExtensionIESONInformationReportIEBindingFieldGet(v *SONInformationExtensionIESONInformationReportIEBinding) *func(*SONInformationExtensionIEIEValue) (*SONInformationReport, bool) {
	return &v.get
}
func BridgeSONInformationExtensionIESONInformationReportIEBindingFieldInfo(v *SONInformationExtensionIESONInformationReportIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeSONInformationExtensionIESONInformationReportIEBindingFieldInject(v *SONInformationExtensionIESONInformationReportIEBinding) *func(SONInformationReport) SONInformationExtensionIEIEValue {
	return &v.inject
}
func BridgeSONInformationExtensionIETableMethodInfoSONInformationReport(v SONInformationExtensionIETable) s00.FieldInfo {
	return v.infoSONInformationReport()
}
func BridgeSONInformationExtensionMethodMarshalAPERBudget(v *SONInformationExtension, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONInformationExtensionMethodMarshalAPERBudgetValue(v *SONInformationExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONInformationExtensionMethodMarshalAPERChanged(v *SONInformationExtension, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONInformationExtensionMethodMarshalAPERChangedValue(v *SONInformationExtension, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONInformationExtensionMethodMarshalAPERLegacy(v *SONInformationExtension) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONInformationExtensionMethodMarshalAPERNewValue(v *SONInformationExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONInformationExtensionMethodMarshalAPERPlanned(v *SONInformationExtension, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONInformationExtensionMethodMarshalAPERTo(v *SONInformationExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationExtensionMethodUnmarshalAPERFrom(v *SONInformationExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationExtensionMethodUnmarshalAPERLegacy(v *SONInformationExtension, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONInformationExtensionMethodUnmarshalAPERWithOptions(v *SONInformationExtension, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONInformationExtensionValueCodecFieldCapture(v *SONInformationExtensionValueCodec) *func(SONInformationExtension, aper.DecodeState) (SONInformationExtension, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationExtensionValueCodecFieldCompare(v *SONInformationExtensionValueCodec) *func(SONInformationExtension, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationExtensionValueCodecFieldContext(v *SONInformationExtensionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationExtensionValueCodecFieldDecode(v *SONInformationExtensionValueCodec) *func([]byte, aper.DecodeState) (SONInformationExtension, error) {
	return &v.decode
}
func BridgeSONInformationExtensionValueCodecFieldEncode(v *SONInformationExtensionValueCodec) *func(SONInformationExtension, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationExtensionValueCodecFieldPath(v *SONInformationExtensionValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationExtensionValueCodecMethodEncodeBudgetValue(v SONInformationExtensionValueCodec, a0 SONInformationExtension, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationExtensionValueCodecMethodEncodeChanged(v SONInformationExtensionValueCodec, a0 SONInformationExtension, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationReportAPERValueFieldContext(v *SONInformationReportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReportAPERValueFieldReceived(v *SONInformationReportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationReportAPERValueFieldReplay(v *SONInformationReportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReportAPERValueFieldWithoutReplay(v *SONInformationReportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReportFieldPerOpenTypePadding(v *SONInformationReport) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSONInformationReportFieldPerPadding(v *SONInformationReport) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONInformationReportFieldReceived(v *SONInformationReport) *bool { return &v.received }
func BridgeSONInformationReportFieldReceivedAbsolute(v *SONInformationReport) *bool {
	return &v.receivedAbsolute
}
func BridgeSONInformationReportFieldReceivedBytes(v *SONInformationReport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONInformationReportFieldReceivedLocation(v *SONInformationReport) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONInformationReportFieldReplay(v *SONInformationReport) *aper.Snapshot { return &v.replay }
func BridgeSONInformationReportFieldStream(v *SONInformationReport) *aper.WireSpan { return &v.stream }
func BridgeSONInformationReportFieldWithoutReplay(v *SONInformationReport) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReportMethodMarshalAPERBudget(v *SONInformationReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONInformationReportMethodMarshalAPERBudgetValue(v *SONInformationReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONInformationReportMethodMarshalAPERChanged(v *SONInformationReport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONInformationReportMethodMarshalAPERChangedValue(v *SONInformationReport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONInformationReportMethodMarshalAPERLegacy(v *SONInformationReport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONInformationReportMethodMarshalAPERNewValue(v *SONInformationReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONInformationReportMethodMarshalAPERPlanned(v *SONInformationReport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONInformationReportMethodMarshalAPERTo(v *SONInformationReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationReportMethodUnmarshalAPERFrom(v *SONInformationReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationReportMethodUnmarshalAPERLegacy(v *SONInformationReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONInformationReportMethodUnmarshalAPERWithOptions(v *SONInformationReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONInformationReportValueCodecFieldCapture(v *SONInformationReportValueCodec) *func(SONInformationReport, aper.DecodeState) (SONInformationReport, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationReportValueCodecFieldCompare(v *SONInformationReportValueCodec) *func(SONInformationReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationReportValueCodecFieldContext(v *SONInformationReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReportValueCodecFieldDecode(v *SONInformationReportValueCodec) *func([]byte, aper.DecodeState) (SONInformationReport, error) {
	return &v.decode
}
func BridgeSONInformationReportValueCodecFieldEncode(v *SONInformationReportValueCodec) *func(SONInformationReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationReportValueCodecFieldPath(v *SONInformationReportValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationReportValueCodecMethodEncodeBudgetValue(v SONInformationReportValueCodec, a0 SONInformationReport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationReportValueCodecMethodEncodeChanged(v SONInformationReportValueCodec, a0 SONInformationReport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONtransferCauseAPERValueFieldContext(v *SONtransferCauseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferCauseAPERValueFieldReceived(v *SONtransferCauseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONtransferCauseAPERValueFieldReplay(v *SONtransferCauseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONtransferCauseAPERValueFieldWithoutReplay(v *SONtransferCauseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONtransferCauseFieldPerOpenTypePadding(v *SONtransferCause) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSONtransferCauseFieldPerPadding(v *SONtransferCause) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONtransferCauseFieldReceived(v *SONtransferCause) *bool { return &v.received }
func BridgeSONtransferCauseFieldReceivedAbsolute(v *SONtransferCause) *bool {
	return &v.receivedAbsolute
}
func BridgeSONtransferCauseFieldReceivedBytes(v *SONtransferCause) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONtransferCauseFieldReceivedLocation(v *SONtransferCause) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONtransferCauseFieldReplay(v *SONtransferCause) *aper.Snapshot { return &v.replay }
func BridgeSONtransferCauseFieldStream(v *SONtransferCause) *aper.WireSpan { return &v.stream }
func BridgeSONtransferCauseFieldWithoutReplay(v *SONtransferCause) *bool   { return &v.withoutReplay }
func BridgeSONtransferCauseMethodMarshalAPERBudget(v *SONtransferCause, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONtransferCauseMethodMarshalAPERBudgetValue(v *SONtransferCause, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONtransferCauseMethodMarshalAPERChanged(v *SONtransferCause, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONtransferCauseMethodMarshalAPERChangedValue(v *SONtransferCause, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONtransferCauseMethodMarshalAPERLegacy(v *SONtransferCause) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONtransferCauseMethodMarshalAPERNewValue(v *SONtransferCause, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONtransferCauseMethodMarshalAPERPlanned(v *SONtransferCause, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONtransferCauseMethodMarshalAPERTo(v *SONtransferCause, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONtransferCauseMethodUnmarshalAPERFrom(v *SONtransferCause, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONtransferCauseMethodUnmarshalAPERLegacy(v *SONtransferCause, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONtransferCauseMethodUnmarshalAPERWithOptions(v *SONtransferCause, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONtransferCauseValueCodecFieldCapture(v *SONtransferCauseValueCodec) *func(SONtransferCause, aper.DecodeState) (SONtransferCause, aper.Snapshot) {
	return &v.capture
}
func BridgeSONtransferCauseValueCodecFieldCompare(v *SONtransferCauseValueCodec) *func(SONtransferCause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONtransferCauseValueCodecFieldContext(v *SONtransferCauseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferCauseValueCodecFieldDecode(v *SONtransferCauseValueCodec) *func([]byte, aper.DecodeState) (SONtransferCause, error) {
	return &v.decode
}
func BridgeSONtransferCauseValueCodecFieldEncode(v *SONtransferCauseValueCodec) *func(SONtransferCause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONtransferCauseValueCodecFieldPath(v *SONtransferCauseValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONtransferCauseValueCodecMethodEncodeBudgetValue(v SONtransferCauseValueCodec, a0 SONtransferCause, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONtransferCauseValueCodecMethodEncodeChanged(v SONtransferCauseValueCodec, a0 SONtransferCause, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSourceNodeIDExtensionAPERValueFieldContext(v *SourceNodeIDExtensionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionAPERValueFieldReceived(v *SourceNodeIDExtensionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceNodeIDExtensionAPERValueFieldReplay(v *SourceNodeIDExtensionAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNodeIDExtensionAPERValueFieldWithoutReplay(v *SourceNodeIDExtensionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSourceNodeIDExtensionFieldPerPadding(v *SourceNodeIDExtension) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSourceNodeIDExtensionFieldReceived(v *SourceNodeIDExtension) *bool { return &v.received }
func BridgeSourceNodeIDExtensionFieldReceivedAbsolute(v *SourceNodeIDExtension) *bool {
	return &v.receivedAbsolute
}
func BridgeSourceNodeIDExtensionFieldReceivedBytes(v *SourceNodeIDExtension) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSourceNodeIDExtensionFieldReceivedLocation(v *SourceNodeIDExtension) *aper.Location {
	return &v.receivedLocation
}
func BridgeSourceNodeIDExtensionFieldReplay(v *SourceNodeIDExtension) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceNodeIDExtensionFieldStream(v *SourceNodeIDExtension) *aper.WireSpan {
	return &v.stream
}
func BridgeSourceNodeIDExtensionFieldWithoutReplay(v *SourceNodeIDExtension) *bool {
	return &v.withoutReplay
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERBudget(v *SourceNodeIDExtension, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERBudgetValue(v *SourceNodeIDExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERChanged(v *SourceNodeIDExtension, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERChangedValue(v *SourceNodeIDExtension, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERLegacy(v *SourceNodeIDExtension) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERNewValue(v *SourceNodeIDExtension, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERPlanned(v *SourceNodeIDExtension, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSourceNodeIDExtensionMethodMarshalAPERTo(v *SourceNodeIDExtension, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceNodeIDExtensionMethodUnmarshalAPERFrom(v *SourceNodeIDExtension, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceNodeIDExtensionMethodUnmarshalAPERLegacy(v *SourceNodeIDExtension, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSourceNodeIDExtensionMethodUnmarshalAPERWithOptions(v *SourceNodeIDExtension, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSourceNodeIDExtensionValueCodecFieldCapture(v *SourceNodeIDExtensionValueCodec) *func(SourceNodeIDExtension, aper.DecodeState) (SourceNodeIDExtension, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNodeIDExtensionValueCodecFieldCompare(v *SourceNodeIDExtensionValueCodec) *func(SourceNodeIDExtension, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNodeIDExtensionValueCodecFieldContext(v *SourceNodeIDExtensionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNodeIDExtensionValueCodecFieldDecode(v *SourceNodeIDExtensionValueCodec) *func([]byte, aper.DecodeState) (SourceNodeIDExtension, error) {
	return &v.decode
}
func BridgeSourceNodeIDExtensionValueCodecFieldEncode(v *SourceNodeIDExtensionValueCodec) *func(SourceNodeIDExtension, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNodeIDExtensionValueCodecFieldPath(v *SourceNodeIDExtensionValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNodeIDExtensionValueCodecMethodEncodeBudgetValue(v SourceNodeIDExtensionValueCodec, a0 SourceNodeIDExtension, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceNodeIDExtensionValueCodecMethodEncodeChanged(v SourceNodeIDExtensionValueCodec, a0 SourceNodeIDExtension, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *RerouteNASRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 0:
		if value, ok := v.AsMMEUES1APID(); ok {
			return value, true
		}
	case 225:
		if value, ok := v.AsS1Message(); ok {
			return value, true
		}
	case 223:
		if value, ok := v.AsMMEGroupID(); ok {
			return value, true
		}
	case 224:
		if value, ok := v.AsAdditionalGUTI(); ok {
			return value, true
		}
	case 230:
		if value, ok := v.AsUEUsageType(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *S1RemovalRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 59:
		if value, ok := v.AsGlobalENBID(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SONInformationExtensionIEIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 206:
		if value, ok := v.AsSONInformationReport(); ok {
			return value, true
		}
	}
	return nil, false
}
