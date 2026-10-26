// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s28 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s28

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UERadioCapabilityMatchResponseIEContainer is ProtocolIE-Container {{UERadioCapabilityMatchResponseIEs}} of TS 36.413: a list of UERadioCapabilityMatchResponseIEField values.
type UERadioCapabilityMatchResponseIEContainer []UERadioCapabilityMatchResponseIEField

// UERadioCapabilityMatchResponseIEField is ProtocolIE-Field {{UERadioCapabilityMatchResponseIEs}} of TS 36.413: an information element field.
type UERadioCapabilityMatchResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UERadioCapabilityMatchResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEField) WithoutReplay() UERadioCapabilityMatchResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UERadioCapabilityMatchResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UERadioCapabilityMatchResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UERadioCapabilityMatchResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchResponseIEField{}
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
	var zero UERadioCapabilityMatchResponseIEValue

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

// UERadioCapabilityIDMappingResponseIEContainer is ProtocolIE-Container {{UERadioCapabilityIDMappingResponseIEs}} of TS 36.413: a list of UERadioCapabilityIDMappingResponseIEField values.
type UERadioCapabilityIDMappingResponseIEContainer []UERadioCapabilityIDMappingResponseIEField

// UERadioCapabilityIDMappingResponseIEField is ProtocolIE-Field {{UERadioCapabilityIDMappingResponseIEs}} of TS 36.413: an information element field.
type UERadioCapabilityIDMappingResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UERadioCapabilityIDMappingResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEField) WithoutReplay() UERadioCapabilityIDMappingResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UERadioCapabilityIDMappingResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UERadioCapabilityIDMappingResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UERadioCapabilityIDMappingResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingResponseIEField{}
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
	var zero UERadioCapabilityIDMappingResponseIEValue

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
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(v *s17.DAPSResponseInfoListIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(v *s17.DAPSResponseInfoListIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *s26.ENBConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(v *s26.ENBConfigurationUpdateAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(v *s26.ENBConfigurationUpdateFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(v *s26.ENBConfigurationUpdateFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(v *s25.ENBStatusTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(v *s25.ENBStatusTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(v *s18.ERABAdmittedItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(v *s18.ERABAdmittedItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIELoggedMBSFNMDTIEBinding binds LoggedMBSFNMDT to the MDTMode-ExtensionIE object set of TS 36.413.
type MDTModeExtensionIELoggedMBSFNMDTIEBinding struct {
	info   s00.FieldInfo
	codec  LoggedMBSFNMDTValueCodec
	inject func(LoggedMBSFNMDT,

	) MDTModeExtensionIEIEValue

	get func(*MDTModeExtensionIEIEValue,

	) (*LoggedMBSFNMDT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Codec() LoggedMBSFNMDTValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) New(value LoggedMBSFNMDT,

) (MDTModeExtensionIEIEField, error) {
	if b.inject == nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Value.New")
	}
	return MDTModeExtensionIEIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MDTModeExtensionIELoggedMBSFNMDTIEBinding) Get(field *MDTModeExtensionIEIEField) (*LoggedMBSFNMDT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// LoggedMBSFNMDTValueCodec is the concrete ValueCodec[LoggedMBSFNMDT].
type LoggedMBSFNMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LoggedMBSFNMDT,

		error)
	encode func(LoggedMBSFNMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LoggedMBSFNMDT, aper.DecodeState,

	) (LoggedMBSFNMDT, aper.Snapshot,

	)
	compare func(LoggedMBSFNMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggedMBSFNMDTValueCodec) New(value LoggedMBSFNMDT,

) (LoggedMBSFNMDTAPERValue, error) {
	if c.encode == nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggedMBSFNMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggedMBSFNMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggedMBSFNMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggedMBSFNMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggedMBSFNMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggedMBSFNMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggedMBSFNMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggedMBSFNMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggedMBSFNMDTValueCodec) EncodeAPER(value LoggedMBSFNMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c LoggedMBSFNMDTValueCodec) encodeBudgetValue(value LoggedMBSFNMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggedMBSFNMDTValueCodec) encodeChanged(value LoggedMBSFNMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEField is ProtocolIE-Field {{MDTMode-ExtensionIE}} of TS 36.413: an information element field.
type MDTModeExtensionIEIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MDTModeExtensionIEIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEField) WithoutReplay() MDTModeExtensionIEIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MDTModeExtensionIEIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MDTModeExtensionIEIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MDTModeExtensionIEIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MDTModeExtensionIEIEField{}
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
	var zero MDTModeExtensionIEIEValue

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

// IntersystemMeasurementConfigurationValueCodec is the concrete ValueCodec[IntersystemMeasurementConfiguration].
type IntersystemMeasurementConfigurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (IntersystemMeasurementConfiguration,

		error)
	encode func(IntersystemMeasurementConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(IntersystemMeasurementConfiguration, aper.DecodeState,

	) (IntersystemMeasurementConfiguration, aper.Snapshot,

	)
	compare func(IntersystemMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntersystemMeasurementConfigurationValueCodec) New(value IntersystemMeasurementConfiguration,

) (IntersystemMeasurementConfigurationAPERValue, error) {
	if c.encode == nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntersystemMeasurementConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntersystemMeasurementConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntersystemMeasurementConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntersystemMeasurementConfigurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntersystemMeasurementConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntersystemMeasurementConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntersystemMeasurementConfigurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntersystemMeasurementConfigurationValueCodec) EncodeAPER(value IntersystemMeasurementConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c IntersystemMeasurementConfigurationValueCodec) encodeBudgetValue(value IntersystemMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntersystemMeasurementConfigurationValueCodec) encodeChanged(value IntersystemMeasurementConfiguration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PC5QoSParametersValueCodec is the concrete ValueCodec[PC5QoSParameters].
type PC5QoSParametersValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PC5QoSParameters,

		error)
	encode func(PC5QoSParameters,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PC5QoSParameters, aper.DecodeState,

	) (PC5QoSParameters, aper.Snapshot,

	)
	compare func(PC5QoSParameters, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PC5QoSParametersValueCodec) New(value PC5QoSParameters,

) (PC5QoSParametersAPERValue, error) {
	if c.encode == nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PC5QoSParametersAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PC5QoSParametersAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PC5QoSParametersValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PC5QoSParametersAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PC5QoSParametersAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PC5QoSParametersAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PC5QoSParametersAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PC5QoSParametersAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PC5QoSParametersValueCodec) EncodeAPER(value PC5QoSParametersAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PC5QoSParametersValueCodec) encodeBudgetValue(value PC5QoSParameters,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PC5QoSParametersValueCodec) encodeChanged(value PC5QoSParameters,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextResumeFailureIEs object set of TS 36.413.
type UEContextResumeFailureMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) s27.UEContextResumeFailureIEValue

	get func(*s27.UEContextResumeFailureIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (s27.UEContextResumeFailureIEField, error) {
	if b.inject == nil {
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(err, "Value.New")
	}
	return s27.UEContextResumeFailureIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeFailureMMEUES1APIDIEBinding) Get(field *s27.UEContextResumeFailureIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding binds UERadioCapabilityID to the UERadioCapabilityIDMappingResponseIEs object set of TS 36.413.
type UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) UERadioCapabilityIDMappingResponseIEValue

	get func(*UERadioCapabilityIDMappingResponseIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding) Get(field *UERadioCapabilityIDMappingResponseIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding binds UERadioCapability to the UERadioCapabilityIDMappingResponseIEs object set of TS 36.413.
type UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) UERadioCapabilityIDMappingResponseIEValue

	get func(*UERadioCapabilityIDMappingResponseIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding) Get(field *UERadioCapabilityIDMappingResponseIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the UERadioCapabilityIDMappingResponseIEs object set of TS 36.413.
type UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) UERadioCapabilityIDMappingResponseIEValue

	get func(*UERadioCapabilityIDMappingResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (UERadioCapabilityIDMappingResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding) Get(field *UERadioCapabilityIDMappingResponseIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseMMEUES1APIDIEBinding binds MMEUES1APID to the UERadioCapabilityMatchResponseIEs object set of TS 36.413.
type UERadioCapabilityMatchResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseMMEUES1APIDIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseENBUES1APIDIEBinding binds ENBUES1APID to the UERadioCapabilityMatchResponseIEs object set of TS 36.413.
type UERadioCapabilityMatchResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseENBUES1APIDIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding binds VoiceSupportMatchIndicator to the UERadioCapabilityMatchResponseIEs object set of TS 36.413.
type UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.VoiceSupportMatchIndicatorValueCodec
	inject func(s00.VoiceSupportMatchIndicator,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s00.VoiceSupportMatchIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Codec() s02.VoiceSupportMatchIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) New(value s00.VoiceSupportMatchIndicator,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s00.VoiceSupportMatchIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the UERadioCapabilityMatchResponseIEs object set of TS 36.413.
type UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) UERadioCapabilityMatchResponseIEValue

	get func(*UERadioCapabilityMatchResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (UERadioCapabilityMatchResponseIEField, error) {
	if b.inject == nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityMatchResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding) Get(field *UERadioCapabilityMatchResponseIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// CellStateIndicationValueCodec is the concrete ValueCodec[CellStateIndication].
type CellStateIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellStateIndication,

		error)
	encode func(CellStateIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellStateIndication, aper.DecodeState,

	) (CellStateIndication, aper.Snapshot,

	)
	compare func(CellStateIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellStateIndicationValueCodec) New(value CellStateIndication,

) (CellStateIndicationAPERValue, error) {
	if c.encode == nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellStateIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellStateIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellStateIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellStateIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellStateIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellStateIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellStateIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellStateIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellStateIndicationValueCodec) EncodeAPER(value CellStateIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellStateIndicationValueCodec) encodeBudgetValue(value CellStateIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellStateIndicationValueCodec) encodeChanged(value CellStateIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge,

		error)
	encode func(ENBConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateAcknowledge, aper.DecodeState,

	) (ENBConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) New(value ENBConfigurationUpdateAcknowledge,

) (ENBConfigurationUpdateAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateAcknowledgeValueCodec) encodeBudgetValue(value ENBConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateAcknowledgeValueCodec) encodeChanged(value ENBConfigurationUpdateAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateFailureValueCodec is the concrete ValueCodec[ENBConfigurationUpdateFailure].
type ENBConfigurationUpdateFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailure,

		error)
	encode func(ENBConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationUpdateFailure, aper.DecodeState,

	) (ENBConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationUpdateFailureValueCodec) New(value ENBConfigurationUpdateFailure,

) (ENBConfigurationUpdateFailureAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationUpdateFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationUpdateFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationUpdateFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationUpdateFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationUpdateFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationUpdateFailureValueCodec) EncodeAPER(value ENBConfigurationUpdateFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBConfigurationUpdateFailureValueCodec) encodeBudgetValue(value ENBConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationUpdateFailureValueCodec) encodeChanged(value ENBConfigurationUpdateFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferValueCodec is the concrete ValueCodec[ENBStatusTransfer].
type ENBStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransfer,

		error)
	encode func(ENBStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransfer, aper.DecodeState,

	) (ENBStatusTransfer, aper.Snapshot,

	)
	compare func(ENBStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferValueCodec) New(value ENBStatusTransfer,

) (ENBStatusTransferAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferValueCodec) EncodeAPER(value ENBStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferValueCodec) encodeBudgetValue(value ENBStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferValueCodec) encodeChanged(value ENBStatusTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterSystemMeasurementParametersValueCodec is the concrete ValueCodec[InterSystemMeasurementParameters].
type InterSystemMeasurementParametersValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemMeasurementParameters,

		error)
	encode func(InterSystemMeasurementParameters,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemMeasurementParameters, aper.DecodeState,

	) (InterSystemMeasurementParameters, aper.Snapshot,

	)
	compare func(InterSystemMeasurementParameters, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemMeasurementParametersValueCodec) New(value InterSystemMeasurementParameters,

) (InterSystemMeasurementParametersAPERValue, error) {
	if c.encode == nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemMeasurementParametersAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemMeasurementParametersValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemMeasurementParametersAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemMeasurementParametersAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemMeasurementParametersAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemMeasurementParametersAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemMeasurementParametersAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemMeasurementParametersValueCodec) EncodeAPER(value InterSystemMeasurementParametersAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InterSystemMeasurementParametersValueCodec) encodeBudgetValue(value InterSystemMeasurementParameters,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemMeasurementParametersValueCodec) encodeChanged(value InterSystemMeasurementParameters,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MultiCellLoadReportingRequestValueCodec is the concrete ValueCodec[MultiCellLoadReportingRequest].
type MultiCellLoadReportingRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MultiCellLoadReportingRequest,

		error)
	encode func(MultiCellLoadReportingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MultiCellLoadReportingRequest, aper.DecodeState,

	) (MultiCellLoadReportingRequest, aper.Snapshot,

	)
	compare func(MultiCellLoadReportingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MultiCellLoadReportingRequestValueCodec) New(value MultiCellLoadReportingRequest,

) (MultiCellLoadReportingRequestAPERValue, error) {
	if c.encode == nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MultiCellLoadReportingRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MultiCellLoadReportingRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MultiCellLoadReportingRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MultiCellLoadReportingRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MultiCellLoadReportingRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MultiCellLoadReportingRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MultiCellLoadReportingRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MultiCellLoadReportingRequestValueCodec) EncodeAPER(value MultiCellLoadReportingRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MultiCellLoadReportingRequestValueCodec) encodeBudgetValue(value MultiCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MultiCellLoadReportingRequestValueCodec) encodeChanged(value MultiCellLoadReportingRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferRequestContainerValueCodec is the concrete ValueCodec[SONtransferRequestContainer].
type SONtransferRequestContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferRequestContainer,

		error)
	encode func(SONtransferRequestContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferRequestContainer, aper.DecodeState,

	) (SONtransferRequestContainer, aper.Snapshot,

	)
	compare func(SONtransferRequestContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferRequestContainerValueCodec) New(value SONtransferRequestContainer,

) (SONtransferRequestContainerAPERValue, error) {
	if c.encode == nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferRequestContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferRequestContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferRequestContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferRequestContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferRequestContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferRequestContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferRequestContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferRequestContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferRequestContainerValueCodec) EncodeAPER(value SONtransferRequestContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONtransferRequestContainerValueCodec) encodeBudgetValue(value SONtransferRequestContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferRequestContainerValueCodec) encodeChanged(value SONtransferRequestContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferResponseContainerValueCodec is the concrete ValueCodec[SONtransferResponseContainer].
type SONtransferResponseContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONtransferResponseContainer,

		error)
	encode func(SONtransferResponseContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONtransferResponseContainer, aper.DecodeState,

	) (SONtransferResponseContainer, aper.Snapshot,

	)
	compare func(SONtransferResponseContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferResponseContainerValueCodec) New(value SONtransferResponseContainer,

) (SONtransferResponseContainerAPERValue, error) {
	if c.encode == nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferResponseContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferResponseContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferResponseContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferResponseContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferResponseContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferResponseContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferResponseContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferResponseContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferResponseContainerValueCodec) EncodeAPER(value SONtransferResponseContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONtransferResponseContainerValueCodec) encodeBudgetValue(value SONtransferResponseContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferResponseContainerValueCodec) encodeChanged(value SONtransferResponseContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DAPSResponseInfoListIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{DAPSResponseInfoListIEs}} codec of TS 36.413.
func DAPSResponseInfoListIEValueERABIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable) s17.DAPSResponseInfoListIEValueERABIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.DAPSResponseInfoListIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.DAPSResponseInfoListIEValueERABIEContainerListValueCodec {
		sealed := s17.DAPSResponseInfoListIEValueERABIEContainerListValueCodec{}
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "DAPSResponseInfoListIEValueERABIEContainerList"
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.DAPSResponseInfoListIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.DAPSResponseInfoListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoListIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.DAPSResponseInfoListIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s17.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.DAPSResponseInfoListIEValueERABIEContainerList, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.DAPSResponseInfoListIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSResponseInfoListIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList"
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBConfigurationUpdateFailureIEs}} codec of TS 36.413.
func ENBConfigurationUpdateFailureIEValueERABIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s26.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateFailureIEValueERABIEContainerList"
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBStatusTransferIEs}} codec of TS 36.413.
func ENBStatusTransferIEValueERABIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable) s25.ENBStatusTransferIEValueERABIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s25.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.ENBStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s25.ENBStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s25.ENBStatusTransferIEValueERABIEContainerListValueCodec{}
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ENBStatusTransferIEValueERABIEContainerList"
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ENBStatusTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.ENBStatusTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.ENBStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.ENBStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s25.ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.ENBStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{E-RABAdmittedItemIEs}} codec of TS 36.413.
func ERABAdmittedItemIEValueERABIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable) s18.ERABAdmittedItemIEValueERABIEContainerListValueCodec {
	codec := ERABAdmittedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABAdmittedItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABAdmittedItemIEValueERABIEContainerListValueCodec {
		sealed := s18.ERABAdmittedItemIEValueERABIEContainerListValueCodec{}
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "ERABAdmittedItemIEValueERABIEContainerList"
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABAdmittedItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABAdmittedItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABAdmittedItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABAdmittedItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABAdmittedItemIEValueERABIEContainerList, options aper.DecodeState) (s18.ERABAdmittedItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABAdmittedItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABAdmittedItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoListIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{DAPSResponseInfoListIEs}} codec of TS 36.413.
func DAPSResponseInfoListIEValueIEFieldTableCodec(table s00.DAPSResponseInfoListIEValueIETable) s17.DAPSResponseInfoListIEFieldValueCodec {
	if !*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&table) {
		return s17.DAPSResponseInfoListIEFieldValueCodec{}
	}
	return func() s17.DAPSResponseInfoListIEFieldValueCodec {
		sealed := s17.DAPSResponseInfoListIEFieldValueCodec{}
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldPath(&sealed) = "DAPSResponseInfoListIEField"
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSResponseInfoListIEField, error) {
			var field s17.DAPSResponseInfoListIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoListIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEField")
			}
			return field, nil
		}
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldEncode(&sealed) = func(field s17.DAPSResponseInfoListIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldCapture(&sealed) = func(v s17.DAPSResponseInfoListIEField, options aper.DecodeState) (s17.DAPSResponseInfoListIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldCompare(&sealed) = func(v s17.DAPSResponseInfoListIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSResponseInfoListIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func ENBConfigurationUpdateAcknowledgeIEValueIEFieldTableCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s26.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec{}
	}
	return func() s26.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec {
		sealed := s26.ENBConfigurationUpdateAcknowledgeIEFieldValueCodec{}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateAcknowledgeIEField"
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEField, error) {
			var field s26.ENBConfigurationUpdateAcknowledgeIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledgeIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEField")
			}
			return field, nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldEncode(&sealed) = func(field s26.ENBConfigurationUpdateAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEField, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBConfigurationUpdateFailureIEs}} codec of TS 36.413.
func ENBConfigurationUpdateFailureIEValueIEFieldTableCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s26.ENBConfigurationUpdateFailureIEFieldValueCodec {
	if !*s00.BridgeENBConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s26.ENBConfigurationUpdateFailureIEFieldValueCodec{}
	}
	return func() s26.ENBConfigurationUpdateFailureIEFieldValueCodec {
		sealed := s26.ENBConfigurationUpdateFailureIEFieldValueCodec{}
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateFailureIEField"
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEField, error) {
			var field s26.ENBConfigurationUpdateFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEField")
			}
			return field, nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s26.ENBConfigurationUpdateFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEField, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBStatusTransferIEs}} codec of TS 36.413.
func ENBStatusTransferIEValueIEFieldTableCodec(table s00.ENBStatusTransferIEValueIETable) s25.ENBStatusTransferIEFieldValueCodec {
	if !*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&table) {
		return s25.ENBStatusTransferIEFieldValueCodec{}
	}
	return func() s25.ENBStatusTransferIEFieldValueCodec {
		sealed := s25.ENBStatusTransferIEFieldValueCodec{}
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldPath(&sealed) = "ENBStatusTransferIEField"
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ENBStatusTransferIEField, error) {
			var field s25.ENBStatusTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBStatusTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ENBStatusTransferIEField")
			}
			return field, nil
		}
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s25.ENBStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s25.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s25.ENBStatusTransferIEField, options aper.DecodeState) (s25.ENBStatusTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s25.ENBStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeENBStatusTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{E-RABAdmittedItemIEs}} codec of TS 36.413.
func ERABAdmittedItemIEValueIEFieldTableCodec(table s00.ERABAdmittedItemIEValueIETable) s18.ERABAdmittedItemIEFieldValueCodec {
	if !*s00.BridgeERABAdmittedItemIEValueIETableFieldBound(&table) {
		return s18.ERABAdmittedItemIEFieldValueCodec{}
	}
	return func() s18.ERABAdmittedItemIEFieldValueCodec {
		sealed := s18.ERABAdmittedItemIEFieldValueCodec{}
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldPath(&sealed) = "ERABAdmittedItemIEField"
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABAdmittedItemIEField, error) {
			var field s18.ERABAdmittedItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABAdmittedItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ERABAdmittedItemIEField")
			}
			return field, nil
		}
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldEncode(&sealed) = func(field s18.ERABAdmittedItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s18.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldCapture(&sealed) = func(v s18.ERABAdmittedItemIEField, options aper.DecodeState) (s18.ERABAdmittedItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldCompare(&sealed) = func(v s18.ERABAdmittedItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABAdmittedItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoListIEValueIETableCodec constructs the ProtocolIE-Container {{DAPSResponseInfoListIEs}} codec of TS 36.413.
func DAPSResponseInfoListIEValueIETableCodec(table s00.DAPSResponseInfoListIEValueIETable, bounds aper.ListBounds) s17.DAPSResponseInfoListIEContainerValueCodec {
	if !*s00.BridgeDAPSResponseInfoListIEValueIETableFieldBound(&table) {
		return s17.DAPSResponseInfoListIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.DAPSResponseInfoListIEContainerValueCodec {
		sealed := s17.DAPSResponseInfoListIEContainerValueCodec{}
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldPath(&sealed) = "DAPSResponseInfoListIEContainer"
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSResponseInfoListIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.DAPSResponseInfoListIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.DAPSResponseInfoListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoListIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEContainer")
			}
			return fields, nil
		}
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.DAPSResponseInfoListIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeDAPSResponseInfoListIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldCapture(&sealed) = func(v s17.DAPSResponseInfoListIEContainer, options aper.DecodeState) (s17.DAPSResponseInfoListIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldCompare(&sealed) = func(v s17.DAPSResponseInfoListIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{ENBConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationUpdateAcknowledgeIEValueIETableFieldBound(&table) {
		return s26.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec {
		sealed := s26.ENBConfigurationUpdateAcknowledgeIEContainerValueCodec{}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateAcknowledgeIEContainer"
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateAcknowledgeIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledgeIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.ENBConfigurationUpdateAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEContainer, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateFailureIEValueIETableCodec constructs the ProtocolIE-Container {{ENBConfigurationUpdateFailureIEs}} codec of TS 36.413.
func ENBConfigurationUpdateFailureIEValueIETableCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s26.ENBConfigurationUpdateFailureIEContainerValueCodec {
	if !*s00.BridgeENBConfigurationUpdateFailureIEValueIETableFieldBound(&table) {
		return s26.ENBConfigurationUpdateFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateFailureIEContainerValueCodec {
		sealed := s26.ENBConfigurationUpdateFailureIEContainerValueCodec{}
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateFailureIEContainer"
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEContainer")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s26.ENBConfigurationUpdateFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEContainer, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{ENBStatusTransferIEs}} codec of TS 36.413.
func ENBStatusTransferIEValueIETableCodec(table s00.ENBStatusTransferIEValueIETable, bounds aper.ListBounds) s25.ENBStatusTransferIEContainerValueCodec {
	if !*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&table) {
		return s25.ENBStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s25.ENBStatusTransferIEContainerValueCodec {
		sealed := s25.ENBStatusTransferIEContainerValueCodec{}
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldPath(&sealed) = "ENBStatusTransferIEContainer"
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ENBStatusTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.ENBStatusTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.ENBStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEContainer")
			}
			return fields, nil
		}
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s25.ENBStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s25.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s25.ENBStatusTransferIEContainer, options aper.DecodeState) (s25.ENBStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s25.ENBStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeENBStatusTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemIEValueIETableCodec constructs the ProtocolIE-Container {{E-RABAdmittedItemIEs}} codec of TS 36.413.
func ERABAdmittedItemIEValueIETableCodec(table s00.ERABAdmittedItemIEValueIETable, bounds aper.ListBounds) s18.ERABAdmittedItemIEContainerValueCodec {
	if !*s00.BridgeERABAdmittedItemIEValueIETableFieldBound(&table) {
		return s18.ERABAdmittedItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABAdmittedItemIEContainerValueCodec {
		sealed := s18.ERABAdmittedItemIEContainerValueCodec{}
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldPath(&sealed) = "ERABAdmittedItemIEContainer"
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABAdmittedItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABAdmittedItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABAdmittedItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEContainer")
			}
			return fields, nil
		}
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s18.ERABAdmittedItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s18.BridgeERABAdmittedItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldCapture(&sealed) = func(v s18.ERABAdmittedItemIEContainer, options aper.DecodeState) (s18.ERABAdmittedItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldCompare(&sealed) = func(v s18.ERABAdmittedItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoListIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{DAPSResponseInfoListIEs}} codec of TS 36.413.
func DAPSResponseInfoListIEValueProtocolErrorIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable) s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "DAPSResponseInfoListIEValueProtocolErrorIEContainerList"
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.DAPSResponseInfoListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoListIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s17.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBConfigurationUpdateAcknowledgeIEs}} codec of TS 36.413.
func ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable) s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList"
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBConfigurationUpdateFailureIEs}} codec of TS 36.413.
func ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable) s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList"
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBStatusTransferIEs}} codec of TS 36.413.
func ENBStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable) s25.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s25.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s25.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s25.ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ENBStatusTransferIEValueProtocolErrorIEContainerList"
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.ENBStatusTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.ENBStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABAdmittedItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{E-RABAdmittedItemIEs}} codec of TS 36.413.
func ERABAdmittedItemIEValueProtocolErrorIEContainerListCodec(table s00.ERABAdmittedItemIEValueIETable) s18.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABAdmittedItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s18.BridgeERABAdmittedItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s18.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s18.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s18.ERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "ERABAdmittedItemIEValueProtocolErrorIEContainerList"
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s18.ERABAdmittedItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABAdmittedItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ERABAdmittedItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s18.BridgeERABAdmittedItemIEContainerValueCodecFieldEncode(&codec))(s18.ERABAdmittedItemIEContainer(value), fresh, budget)
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABAdmittedItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABAdmittedItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DAPSResponseInfoListIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {DAPSResponseInfoListIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func DAPSResponseInfoListIEValueProtocolIEContainerListCodec(table s00.DAPSResponseInfoListIEValueIETable, bounds aper.ListBounds) s17.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec {
	codec := DAPSResponseInfoListIEValueIETableCodec(table, bounds)
	if *s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s17.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec {
		sealed := s17.DAPSResponseInfoListIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "DAPSResponseInfoListIEValueProtocolIEContainerList"
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.DAPSResponseInfoListIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.DAPSResponseInfoListIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoListIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "DAPSResponseInfoListIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.DAPSResponseInfoListIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeDAPSResponseInfoListIEContainerValueCodecFieldEncode(&codec))(s17.DAPSResponseInfoListIEContainer(value), fresh, budget)
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.DAPSResponseInfoListIEValueProtocolIEContainerList, options aper.DecodeState) (s17.DAPSResponseInfoListIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.DAPSResponseInfoListIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeDAPSResponseInfoListIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationUpdateAcknowledgeIEValueIETable, bounds aper.ListBounds) s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationUpdateAcknowledgeIEValueIETableCodec(table, bounds)
	if *s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList"
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateAcknowledgeIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateAcknowledgeIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateAcknowledgeIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBConfigurationUpdateFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationUpdateFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBConfigurationUpdateFailureIEValueProtocolIEContainerListCodec(table s00.ENBConfigurationUpdateFailureIEValueIETable, bounds aper.ListBounds) s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
	codec := ENBConfigurationUpdateFailureIEValueIETableCodec(table, bounds)
	if *s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodec{}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ENBConfigurationUpdateFailureIEValueProtocolIEContainerList"
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s26.ENBConfigurationUpdateFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s26.BridgeENBConfigurationUpdateFailureIEContainerValueCodecFieldEncode(&codec))(s26.ENBConfigurationUpdateFailureIEContainer(value), fresh, budget)
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeENBConfigurationUpdateFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBStatusTransferIEValueProtocolIEContainerListCodec(table s00.ENBStatusTransferIEValueIETable, bounds aper.ListBounds) s25.ENBStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBStatusTransferIEValueIETableCodec(table, bounds)
	if *s25.BridgeENBStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s25.ENBStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s25.ENBStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s25.ENBStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "ENBStatusTransferIEValueProtocolIEContainerList"
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.ENBStatusTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s25.ENBStatusTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s25.ENBStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "ENBStatusTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ENBStatusTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s25.ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s25.BridgeENBStatusTransferIEContainerValueCodecFieldEncode(&codec))(s25.ENBStatusTransferIEContainer(value), fresh, budget)
		}
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s25.ENBStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s25.ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s25.ENBStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// dAPSResponseInfoListIEValueProtocolOpenValue is the concrete protocolOpenValue[DAPSResponseInfoListIEValue].
type DAPSResponseInfoListIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.DAPSResponseInfoListIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.DAPSResponseInfoListIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(v *s17.DAPSResponseInfoListIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeDAPSResponseInfoListIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeDAPSResponseInfoListIEFieldFieldReplay(v), *s17.BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v))
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(v *s17.DAPSResponseInfoListIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeDAPSResponseInfoListIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeDAPSResponseInfoListIEFieldFieldReplay(v), *s17.BridgeDAPSResponseInfoListIEFieldFieldWithoutReplay(v))
}

// eNBConfigurationUpdateAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationUpdateAcknowledgeIEValue].
type ENBConfigurationUpdateAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.ENBConfigurationUpdateAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.ENBConfigurationUpdateAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v *s26.ENBConfigurationUpdateAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v *s26.ENBConfigurationUpdateAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeENBConfigurationUpdateAcknowledgeIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldReplay(v), *s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldFieldWithoutReplay(v))
}

// eNBConfigurationUpdateFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBConfigurationUpdateFailureIEValue].
type ENBConfigurationUpdateFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s26.ENBConfigurationUpdateFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s26.ENBConfigurationUpdateFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v *s26.ENBConfigurationUpdateFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s26.BridgeENBConfigurationUpdateFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s26.BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v), *s26.BridgeENBConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v *s26.ENBConfigurationUpdateFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s26.BridgeENBConfigurationUpdateFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s26.BridgeENBConfigurationUpdateFailureIEFieldFieldReplay(v), *s26.BridgeENBConfigurationUpdateFailureIEFieldFieldWithoutReplay(v))
}

// eNBStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBStatusTransferIEValue].
type ENBStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s25.ENBStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s25.ENBStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(v *s25.ENBStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s25.BridgeENBStatusTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s25.BridgeENBStatusTransferIEFieldFieldReplay(v), *s25.BridgeENBStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(v *s25.ENBStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s25.BridgeENBStatusTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s25.BridgeENBStatusTransferIEFieldFieldReplay(v), *s25.BridgeENBStatusTransferIEFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(v *s18.ERABAdmittedItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s18.BridgeERABAdmittedItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s18.BridgeERABAdmittedItemIEFieldFieldReplay(v), *s18.BridgeERABAdmittedItemIEFieldFieldWithoutReplay(v))
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(v *s18.ERABAdmittedItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s18.BridgeERABAdmittedItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s18.BridgeERABAdmittedItemIEFieldFieldReplay(v), *s18.BridgeERABAdmittedItemIEFieldFieldWithoutReplay(v))
}

// LoggedMBSFNMDTAPERValue is the concrete APERValue[LoggedMBSFNMDT].
type LoggedMBSFNMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   LoggedMBSFNMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggedMBSFNMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggedMBSFNMDTAPERValue) WithoutReplay() LoggedMBSFNMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntersystemMeasurementConfigurationAPERValue is the concrete APERValue[IntersystemMeasurementConfiguration].
type IntersystemMeasurementConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   IntersystemMeasurementConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntersystemMeasurementConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemMeasurementConfigurationAPERValue) WithoutReplay() IntersystemMeasurementConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PC5QoSParametersAPERValue is the concrete APERValue[PC5QoSParameters].
type PC5QoSParametersAPERValue struct {
	context s00.BridgeCodecContext
	Value   PC5QoSParameters

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PC5QoSParametersAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PC5QoSParametersAPERValue) WithoutReplay() PC5QoSParametersAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellStateIndicationAPERValue is the concrete APERValue[CellStateIndication].
type CellStateIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellStateIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellStateIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellStateIndicationAPERValue) WithoutReplay() CellStateIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationUpdateAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateFailureAPERValue is the concrete APERValue[ENBConfigurationUpdateFailure].
type ENBConfigurationUpdateFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBConfigurationUpdateFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationUpdateFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationUpdateFailureAPERValue) WithoutReplay() ENBConfigurationUpdateFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferAPERValue is the concrete APERValue[ENBStatusTransfer].
type ENBStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferAPERValue) WithoutReplay() ENBStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterSystemMeasurementParametersAPERValue is the concrete APERValue[InterSystemMeasurementParameters].
type InterSystemMeasurementParametersAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterSystemMeasurementParameters

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemMeasurementParametersAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemMeasurementParametersAPERValue) WithoutReplay() InterSystemMeasurementParametersAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MultiCellLoadReportingRequestAPERValue is the concrete APERValue[MultiCellLoadReportingRequest].
type MultiCellLoadReportingRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   MultiCellLoadReportingRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MultiCellLoadReportingRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MultiCellLoadReportingRequestAPERValue) WithoutReplay() MultiCellLoadReportingRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferRequestContainerAPERValue is the concrete APERValue[SONtransferRequestContainer].
type SONtransferRequestContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferRequestContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferRequestContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferRequestContainerAPERValue) WithoutReplay() SONtransferRequestContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferResponseContainerAPERValue is the concrete APERValue[SONtransferResponseContainer].
type SONtransferResponseContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONtransferResponseContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferResponseContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferResponseContainerAPERValue) WithoutReplay() SONtransferResponseContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APERABIEContainerList(v *s17.DAPSResponseInfoListIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APERABIEContainerList(v *s17.DAPSResponseInfoListIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APERABIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APERABIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APERABIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APERABIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APERABIEContainerList(v *s25.ENBStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APERABIEContainerList(v *s25.ENBStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APERABIEContainerList(v *s18.ERABAdmittedItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APERABIEContainerList(v *s18.ERABAdmittedItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MDTModeExtensionIEIEValueERABIEContainerList].
type MDTModeExtensionIEIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueERABIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueERABIEContainerList) (MDTModeExtensionIEIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueERABIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MDTMode-ExtensionIE}} of TS 36.413: a list of information element fields.
type MDTModeExtensionIEIEValueERABIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// MDTModeExtensionIEIEContainer is ProtocolIE-Container {{MDTMode-ExtensionIE}} of TS 36.413: a list of MDTModeExtensionIEIEField values.
type MDTModeExtensionIEIEContainer []MDTModeExtensionIEIEField

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponseIEValueERABIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error)
	encode  func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) New(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} of TS 36.413: a list of information element fields.
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponseIEValueERABIEContainerList].
type UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueERABIEContainerList) (UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} of TS 36.413: a list of information element fields.
type UERadioCapabilityMatchResponseIEValueERABIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

// MDTModeExtensionIEIEFieldValueCodec is the concrete ValueCodec[MDTModeExtensionIEIEField].
type MDTModeExtensionIEIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEField, error)
	encode  func(MDTModeExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEField, aper.DecodeState) (MDTModeExtensionIEIEField, aper.Snapshot)
	compare func(MDTModeExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEFieldValueCodec) New(value MDTModeExtensionIEIEField) (MDTModeExtensionIEIEFieldAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEFieldValueCodec) EncodeAPER(value MDTModeExtensionIEIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionIEIEFieldValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEFieldValueCodec) encodeChanged(value MDTModeExtensionIEIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEFieldValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponseIEField].
type UERadioCapabilityIDMappingResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, error)
	encode  func(UERadioCapabilityIDMappingResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEField, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) New(value UERadioCapabilityIDMappingResponseIEField) (UERadioCapabilityIDMappingResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEFieldValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEFieldValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponseIEField].
type UERadioCapabilityMatchResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, error)
	encode  func(UERadioCapabilityMatchResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEField, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) New(value UERadioCapabilityMatchResponseIEField) (UERadioCapabilityMatchResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEFieldValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainer(v *s17.DAPSResponseInfoListIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainer(v *s17.DAPSResponseInfoListIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainer(v *s18.ERABAdmittedItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainer(v *s18.ERABAdmittedItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEContainerValueCodec is the concrete ValueCodec[MDTModeExtensionIEIEContainer].
type MDTModeExtensionIEIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEContainer, error)
	encode  func(MDTModeExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEContainer, aper.DecodeState) (MDTModeExtensionIEIEContainer, aper.Snapshot)
	compare func(MDTModeExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEContainerValueCodec) New(value MDTModeExtensionIEIEContainer) (MDTModeExtensionIEIEContainerAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEContainerValueCodec) EncodeAPER(value MDTModeExtensionIEIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionIEIEContainerValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEContainerValueCodec) encodeChanged(value MDTModeExtensionIEIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEContainerValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponseIEContainer].
type UERadioCapabilityIDMappingResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, error)
	encode  func(UERadioCapabilityIDMappingResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEContainer, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) New(value UERadioCapabilityIDMappingResponseIEContainer) (UERadioCapabilityIDMappingResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEContainerValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEContainerValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponseIEContainer].
type UERadioCapabilityMatchResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, error)
	encode  func(UERadioCapabilityMatchResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEContainer, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) New(value UERadioCapabilityMatchResponseIEContainer) (UERadioCapabilityMatchResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEContainerValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolErrorIEContainerList(v *s17.DAPSResponseInfoListIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s25.ENBStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolErrorIEContainerList(v *s18.ERABAdmittedItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MDTModeExtensionIEIEValueProtocolErrorIEContainerList].
type MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList) (MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MDTMode-ExtensionIE}} of TS 36.413: a list of information element fields.
type MDTModeExtensionIEIEValueProtocolErrorIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} of TS 36.413: a list of information element fields.
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList].
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} of TS 36.413: a list of information element fields.
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

func BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIEContainerList(v *s17.DAPSResponseInfoListIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIEContainerList(v *s17.DAPSResponseInfoListIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainerList(v *s26.ENBConfigurationUpdateFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *s25.ENBStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainerList(v *s25.ENBStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABAdmittedItemIEValueCaptureS1APProtocolIEContainerList(v *s18.ERABAdmittedItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABAdmittedItemIEValueCompareS1APProtocolIEContainerList(v *s18.ERABAdmittedItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MDTModeExtensionIEIEValueProtocolIEContainerList].
type MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, error)
	encode  func(MDTModeExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) New(value MDTModeExtensionIEIEValueProtocolIEContainerList) (MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) encodeChanged(value MDTModeExtensionIEIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTModeExtensionIEIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MDTMode-ExtensionIE} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MDTModeExtensionIEIEValueProtocolIEContainerList []MDTModeExtensionIEIEValueProtocolIESingleContainer

// UEContextResumeFailureIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeFailureIEValueProtocolIEContainerList].
type UEContextResumeFailureIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, error)
	encode  func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) New(value s27.UEContextResumeFailureIEValueProtocolIEContainerList) (s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue {
			sealed := s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{Value: value}
			*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReplay(&sealed) = replay
			*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) EncodeAPER(value s27.UEContextResumeFailureIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldContext(&value) == c.context && !fresh && (*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s27.BridgeUEContextResumeFailureIEValueProtocolIEContainerListAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value s27.UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) encodeChanged(value s27.UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error)
	encode  func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) New(value UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityIDMappingResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList []UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponseIEValueProtocolIEContainerList].
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error)
	encode  func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) New(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerList []UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer

func BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *s26.ENBConfigurationUpdateAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIESingleContainer(v *s26.ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIESingleContainer(v *s26.ENBConfigurationUpdateFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *s25.ENBStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *s25.ENBStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MDTModeExtensionIEIEValueERABIEContainerListAPERValue is the concrete APERValue[MDTModeExtensionIEIEValueERABIEContainerList].
type MDTModeExtensionIEIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueERABIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MDTMode-ExtensionIE}} of TS 36.413: a single information element field.
type MDTModeExtensionIEIEValueProtocolIESingleContainer = MDTModeExtensionIEIEField

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponseIEValueERABIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UERadioCapabilityIDMappingResponseIEs}} of TS 36.413: a single information element field.
type UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer = UERadioCapabilityIDMappingResponseIEField

// UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityMatchResponseIEValueERABIEContainerList].
type UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UERadioCapabilityMatchResponseIEs}} of TS 36.413: a single information element field.
type UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer = UERadioCapabilityMatchResponseIEField

// MDTModeExtensionIEIEFieldAPERValue is the concrete APERValue[MDTModeExtensionIEIEField].
type MDTModeExtensionIEIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEFieldAPERValue) WithoutReplay() MDTModeExtensionIEIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEFieldAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponseIEField].
type UERadioCapabilityIDMappingResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEFieldAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEFieldAPERValue is the concrete APERValue[UERadioCapabilityMatchResponseIEField].
type UERadioCapabilityMatchResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEFieldAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEContainerAPERValue is the concrete APERValue[MDTModeExtensionIEIEContainer].
type MDTModeExtensionIEIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEContainerAPERValue) WithoutReplay() MDTModeExtensionIEIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEContainerAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponseIEContainer].
type UERadioCapabilityIDMappingResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEContainerAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEContainerAPERValue is the concrete APERValue[UERadioCapabilityMatchResponseIEContainer].
type UERadioCapabilityMatchResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEContainerAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MDTModeExtensionIEIEValueProtocolErrorIEContainerList].
type MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList].
type UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MDTModeExtensionIEIEValueProtocolIEContainerList].
type MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MDTModeExtensionIEIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue) WithoutReplay() MDTModeExtensionIEIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList].
type UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UERadioCapabilityMatchResponseIEValueProtocolIEContainerList].
type UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UERadioCapabilityMatchResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UERadioCapabilityMatchResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APCellStateIndication(v *CellStateIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APNotificationCellList(&v.NotificationCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellStateIndication(v *CellStateIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APNotificationCellList(&v.NotificationCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoList(v *s17.DAPSResponseInfoList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APDAPSResponseInfoList(v *s17.DAPSResponseInfoList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDAPSResponseInfoListIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APECGIList(v *s20.ECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APECGIListForRestart(v *s20.ECGIListForRestart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBConfigurationUpdateFailure(v *ENBConfigurationUpdateFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBConfigurationUpdateFailure(v *ENBConfigurationUpdateFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBConfigurationUpdateFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBStatusTransfer(v *ENBStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBStatusTransfer(v *ENBStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2ExtTLAs(v *s18.ENBX2ExtTLAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s18.BridgeCompareS1APENBX2ExtTLA(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APERABAdmittedList(v *s18.ERABAdmittedList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APERABAdmittedList(v *s18.ERABAdmittedList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeERABAdmittedItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaIDBroadcast(v *s26.EmergencyAreaIDBroadcast, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s26.BridgeCompareS1APEmergencyAreaIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaIDCancelled(v *s25.EmergencyAreaIDCancelled, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s25.BridgeCompareS1APEmergencyAreaIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenLAs(v *s21.ForbiddenLAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s21.BridgeCompareS1APForbiddenLAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenTAs(v *s21.ForbiddenTAs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s21.BridgeCompareS1APForbiddenTAsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGUMMEIList(v *s21.GUMMEIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s21.BridgeCompareS1APGUMMEI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIEsECGIList(v *s21.IEsECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APInterSystemMeasurementList(v *s21.InterSystemMeasurementList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s21.BridgeCompareS1APInterSystemMeasurementItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APInterSystemMeasurementParameters(v *InterSystemMeasurementParameters, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MeasurementDuration))
	s.Bool(v.InterSystemMeasurementList == nil)
	s25.BridgeCaptureS1APInterSystemMeasurementList(&v.InterSystemMeasurementList, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeInterSystemMeasurementParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInterSystemMeasurementParameters(v *InterSystemMeasurementParameters, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.MeasurementDuration))
	s.Bool(v.InterSystemMeasurementList == nil)
	BridgeCompareS1APInterSystemMeasurementList(&v.InterSystemMeasurementList, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeInterSystemMeasurementParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APIntersystemMeasurementConfiguration(v *IntersystemMeasurementConfiguration, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.RSRP == nil)
		if v.RSRP != nil {
			s.Int(int64((*v.RSRP)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.RSRQ == nil)
		if v.RSRQ != nil {
			s.Int(int64((*v.RSRQ)))
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SINR == nil)
		if v.SINR != nil {
			s.Int(int64((*v.SINR)))
		}
		s.End(f, nil, false)
	}
	BridgeCaptureS1APInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeIntersystemMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APIntersystemMeasurementConfiguration(v *IntersystemMeasurementConfiguration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.RSRP == nil)
		if v.RSRP != nil {
			s.Int(int64((*v.RSRP)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.RSRQ == nil)
		if v.RSRQ != nil {
			s.Int(int64((*v.RSRQ)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SINR == nil)
		if v.SINR != nil {
			s.Int(int64((*v.SINR)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	BridgeCompareS1APInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeIntersystemMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APLastVisitedPSCellList(v *s23.LastVisitedPSCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s23.BridgeCompareS1APLastVisitedPSCellInformation(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APLoggedMBSFNMDT(v *LoggedMBSFNMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APLoggingInterval(&v.LoggingInterval, s)
	s00.BridgeCaptureS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.MBSFNResultToLog == nil)
	s25.BridgeCaptureS1APMBSFNResultToLog(&v.MBSFNResultToLog, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeLoggedMBSFNMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLoggedMBSFNMDT(v *LoggedMBSFNMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APLoggingInterval(&v.LoggingInterval, s)
	s02.BridgeCompareS1APLoggingDuration(&v.LoggingDuration, s)
	s.Bool(v.MBSFNResultToLog == nil)
	BridgeCompareS1APMBSFNResultToLog(&v.MBSFNResultToLog, s)
	s.Bool(v.IEExtensions == nil)
	s16.BridgeLoggedMBSFNMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APMBSFNResultToLog(v *s22.MBSFNResultToLog, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s22.BridgeCompareS1APMBSFNResultToLogInfo(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APMDTModeExtensionIEIEValue(v *MDTModeExtensionIEIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(197):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMBSFNMDT == nil)
				if v.rowLoggedMBSFNMDT != nil {
					BridgeCaptureS1APLoggedMBSFNMDT(v.rowLoggedMBSFNMDT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTModeExtensionIEIEValue) captureSemantics(s aper.SemanticCapture) MDTModeExtensionIEIEValue {
	BridgeCaptureS1APMDTModeExtensionIEIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMDTModeExtensionIEIEValue(v *MDTModeExtensionIEIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(197):
			{
				f := s.Begin()
				s.Bool(v.rowLoggedMBSFNMDT == nil)
				if v.rowLoggedMBSFNMDT != nil {
					BridgeCompareS1APLoggedMBSFNMDT(v.rowLoggedMBSFNMDT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MDTModeExtensionIEIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMDTModeExtensionIEIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMultiCellLoadReportingRequest(v *MultiCellLoadReportingRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APRequestedCellList(&v.RequestedCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMultiCellLoadReportingRequest(v *MultiCellLoadReportingRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APRequestedCellList(&v.RequestedCellList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APMultiCellLoadReportingResponse(v *s22.MultiCellLoadReportingResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s22.BridgeCompareS1APMultiCellLoadReportingResponseItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNotificationCellList(v *s23.NotificationCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s23.BridgeCompareS1APNotificationCellListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPC5QoSFlowList(v *s23.PC5QoSFlowList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s23.BridgeCompareS1APPC5QoSFlowItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APPC5QoSParameters(v *PC5QoSParameters, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APPC5QoSFlowList(&v.Pc5QoSFlowList, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5LinkAggregatedBitRates == nil)
		if v.Pc5LinkAggregatedBitRates != nil {
			s00.BridgeCaptureS1APBitRate(v.Pc5LinkAggregatedBitRates, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s16.BridgePC5QoSParametersExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPC5QoSParameters(v *PC5QoSParameters, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APPC5QoSFlowList(&v.Pc5QoSFlowList, s)
	{
		f := s.Begin()
		s.Bool(v.Pc5LinkAggregatedBitRates == nil)
		if v.Pc5LinkAggregatedBitRates != nil {
			s02.BridgeCompareS1APBitRate(v.Pc5LinkAggregatedBitRates, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s16.BridgePC5QoSParametersExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCompareS1APPWSfailedECGIList(v *s23.PWSfailedECGIList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s20.BridgeCompareS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRATRestrictions(v *s23.RATRestrictions, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s23.BridgeCompareS1APRATRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APReportingCellList(v *s23.ReportingCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s23.BridgeCompareS1APReportingCellListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APRequestedCellList(v *s23.RequestedCellList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			s21.BridgeCompareS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APSONtransferRequestContainer(v *SONtransferRequestContainer, s *aper.SemanticCapture) {
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
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				BridgeCaptureS1APMultiCellLoadReportingRequest(v.MultiCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s21.BridgeCaptureS1APEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s25.BridgeCaptureS1APHOReport(v.HOReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s26.BridgeCaptureS1APCellActivationRequest(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				BridgeCaptureS1APCellStateIndication(v.EnergySavingsIndication, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferRequestContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s24.BridgeCaptureS1APFailureEventReport(v.FailureEventReporting, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferRequestContainer(v *SONtransferRequestContainer, s *aper.SemanticComparison) {
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
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.MultiCellLoadReporting == nil)
			if v.MultiCellLoadReporting != nil {
				BridgeCompareS1APMultiCellLoadReportingRequest(v.MultiCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s21.BridgeCompareS1APEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
				s25.BridgeCompareS1APHOReport(v.HOReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s26.BridgeCompareS1APCellActivationRequest(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
				BridgeCompareS1APCellStateIndication(v.EnergySavingsIndication, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferRequestContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
				s24.BridgeCompareS1APFailureEventReport(v.FailureEventReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APSONtransferResponseContainer(v *SONtransferResponseContainer, s *aper.SemanticCapture) {
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
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s21.BridgeCaptureS1APCellLoadReportingResponse(v.CellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
		s25.BridgeCaptureS1APMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, s)
	case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s21.BridgeCaptureS1APEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s25.BridgeCaptureS1APCellActivationResponse(v.EutranCellActivation, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
			}
			s.End(f, nil, false)
		}
	case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONtransferResponseContainer(v *SONtransferResponseContainer, s *aper.SemanticComparison) {
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
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.CellLoadReporting == nil)
			if v.CellLoadReporting != nil {
				s21.BridgeCompareS1APCellLoadReportingResponse(v.CellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
		BridgeCompareS1APMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, s)
	case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
		{
			f := s.Begin()
			s.Bool(v.EventTriggeredCellLoadReporting == nil)
			if v.EventTriggeredCellLoadReporting != nil {
				s21.BridgeCompareS1APEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceHOReporting:
		{
			f := s.Begin()
			s.Bool(v.HOReporting == nil)
			if v.HOReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceEutranCellActivation:
		{
			f := s.Begin()
			s.Bool(v.EutranCellActivation == nil)
			if v.EutranCellActivation != nil {
				s25.BridgeCompareS1APCellActivationResponse(v.EutranCellActivation, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		{
			f := s.Begin()
			s.Bool(v.EnergySavingsIndication == nil)
			if v.EnergySavingsIndication != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		{
			f := s.Begin()
			s.Bool(v.FailureEventReporting == nil)
			if v.FailureEventReporting != nil {
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APUERadioCapabilityIDMappingResponseIEValue(v *UERadioCapabilityIDMappingResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s00.BridgeCaptureS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingResponseIEValue) captureSemantics(s aper.SemanticCapture) UERadioCapabilityIDMappingResponseIEValue {
	BridgeCaptureS1APUERadioCapabilityIDMappingResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUERadioCapabilityIDMappingResponseIEValue(v *UERadioCapabilityIDMappingResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s08.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s08.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityIDMappingResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUERadioCapabilityIDMappingResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUERadioCapabilityMatchResponseIEValue(v *UERadioCapabilityMatchResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(169):
			{
				f := s.Begin()
				s.Bool(v.rowVoiceSupportMatchIndicator == nil)
				if v.rowVoiceSupportMatchIndicator != nil {
					s00.BridgeCaptureS1APVoiceSupportMatchIndicator(v.rowVoiceSupportMatchIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityMatchResponseIEValue) captureSemantics(s aper.SemanticCapture) UERadioCapabilityMatchResponseIEValue {
	BridgeCaptureS1APUERadioCapabilityMatchResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUERadioCapabilityMatchResponseIEValue(v *UERadioCapabilityMatchResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(169):
			{
				f := s.Begin()
				s.Bool(v.rowVoiceSupportMatchIndicator == nil)
				if v.rowVoiceSupportMatchIndicator != nil {
					s08.BridgeCompareS1APVoiceSupportMatchIndicator(v.rowVoiceSupportMatchIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UERadioCapabilityMatchResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUERadioCapabilityMatchResponseIEValue(&v, &s)
	return s
}

// IntersystemMeasurementConfiguration represents the ASN.1 type IntersystemMeasurementConfiguration (SEQUENCE).
type IntersystemMeasurementConfiguration struct {
	replay                           aper.Snapshot
	stream                           aper.WireSpan
	received                         bool
	withoutReplay                    bool
	receivedAbsolute                 bool
	receivedBytes                    aper.WireSpan
	receivedLocation                 aper.Location
	RSRP                             *int64                                                    `asn1:"tag:0,context,implicit,optional" json:"RSRP,omitempty"`
	RSRQ                             *int64                                                    `asn1:"tag:1,context,implicit,optional" json:"RSRQ,omitempty"`
	SINR                             *int64                                                    `asn1:"tag:2,context,implicit,optional" json:"SINR,omitempty"`
	InterSystemMeasurementParameters InterSystemMeasurementParameters                          `asn1:"tag:3,context,implicit"`
	IEExtensions                     s11.IntersystemMeasurementConfigurationExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                bool                                                      `asn1:"-" json:"-"`
	extCount                         int64                                                     `asn1:"-" json:"-"`
	extPresent                       []bool                                                    `asn1:"-" json:"-"`
	extData                          [][]byte                                                  `asn1:"-" json:"-"`
	perPadding                       aper.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding                    []aper.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin                        []aper.OpaqueOrigin
	extWire                          []aper.WireSpan
}

// InterSystemMeasurementParameters represents the ASN.1 type InterSystemMeasurementParameters (SEQUENCE).
type InterSystemMeasurementParameters struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	MeasurementDuration             int64                                                  `asn1:"tag:0,context,implicit"`
	InterSystemMeasurementList      s21.InterSystemMeasurementList                         `asn1:"tag:1,context,implicit,optional" json:"InterSystemMeasurementList,omitzero"`
	interSystemMeasurementListIndef bool                                                   `asn1:"-" json:"-"`
	IEExtensions                    s11.InterSystemMeasurementParametersExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef               bool                                                   `asn1:"-" json:"-"`
	extCount                        int64                                                  `asn1:"-" json:"-"`
	extPresent                      []bool                                                 `asn1:"-" json:"-"`
	extData                         [][]byte                                               `asn1:"-" json:"-"`
	perPadding                      aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding                   []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin                       []aper.OpaqueOrigin
	extWire                         []aper.WireSpan
}

// LoggedMBSFNMDT represents the ASN.1 type LoggedMBSFNMDT (SEQUENCE).
type LoggedMBSFNMDT struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	LoggingInterval       s00.LoggingInterval                  `asn1:"tag:0,context,implicit"`
	LoggingDuration       s00.LoggingDuration                  `asn1:"tag:1,context,implicit"`
	MBSFNResultToLog      s22.MBSFNResultToLog                 `asn1:"tag:2,context,implicit,optional" json:"MBSFNResultToLog,omitzero"`
	mBSFNResultToLogIndef bool                                 `asn1:"-" json:"-"`
	IEExtensions          s11.LoggedMBSFNMDTExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                 `asn1:"-" json:"-"`
	extCount              int64                                `asn1:"-" json:"-"`
	extPresent            []bool                               `asn1:"-" json:"-"`
	extData               [][]byte                             `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// PC5QoSParameters represents the ASN.1 type PC5QoSParameters (SEQUENCE).
type PC5QoSParameters struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	Pc5QoSFlowList            s23.PC5QoSFlowList                     `asn1:"tag:0,context,implicit"`
	pc5QoSFlowListIndef       bool                                   `asn1:"-" json:"-"`
	Pc5LinkAggregatedBitRates *s00.BitRate                           `asn1:"tag:1,context,implicit,optional" json:"Pc5LinkAggregatedBitRates,omitempty"`
	IEExtensions              s12.PC5QoSParametersExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                   `asn1:"-" json:"-"`
	extCount                  int64                                  `asn1:"-" json:"-"`
	extPresent                []bool                                 `asn1:"-" json:"-"`
	extData                   [][]byte                               `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// MarshalAPER encodes IntersystemMeasurementConfiguration to APER format.
func (v *IntersystemMeasurementConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.RSRP != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.RSRQ != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SINR != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.RSRP != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.RSRP), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding rSRP: %w", err)
		}
	}
	if v.RSRQ != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.RSRQ), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding rSRQ: %w", err)
		}
	}
	if v.SINR != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SINR), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sINR: %w", err)
		}
	}
	if err := v.InterSystemMeasurementParameters.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding interSystemMeasurementParameters: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes IntersystemMeasurementConfiguration from APER format.
func (v *IntersystemMeasurementConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *IntersystemMeasurementConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	bb.EnterComponent("IntersystemMeasurementConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "IntersystemMeasurementConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
	}
	v.perPadding = padding
	return nil
}
func (v *IntersystemMeasurementConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = IntersystemMeasurementConfiguration{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rsrp, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_rsrq, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_sinr, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_rsrp {
		val_rsrp, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "RSRP")
		}
		if err := aper.ChargeValue(bb, val_rsrp); err != nil {
			return err
		}
		v.RSRP = (*int64)(bb.OwnInt64(int64(val_rsrp)))

	}
	if opt_rsrq {
		val_rsrq, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "RSRQ")
		}
		if err := aper.ChargeValue(bb, val_rsrq); err != nil {
			return err
		}
		v.RSRQ = (*int64)(bb.OwnInt64(int64(val_rsrq)))

	}
	if opt_sinr {
		val_sinr, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SINR")
		}
		if err := aper.ChargeValue(bb, val_sinr); err != nil {
			return err
		}
		v.SINR = (*int64)(bb.OwnInt64(int64(val_sinr)))

	}
	toleranceMark_intersystemmeasurementparameters := bb.EnterComponent("InterSystemMeasurementParameters")
	if err := v.InterSystemMeasurementParameters.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	bb.LeaveComponent(toleranceMark_intersystemmeasurementparameters)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.IntersystemMeasurementConfigurationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.IntersystemMeasurementConfigurationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeIntersystemMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes InterSystemMeasurementParameters to APER format.
func (v *InterSystemMeasurementParameters) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InterSystemMeasurementParameters) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.InterSystemMeasurementList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.MeasurementDuration), s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding measurementDuration: %w", err)
	}
	if v.InterSystemMeasurementList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.InterSystemMeasurementList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_intersystemmeasurementlist, fragmentLength_intersystemmeasurementlist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_intersystemmeasurementlist < 0 || fragmentOffset_intersystemmeasurementlist > int64(len(v.InterSystemMeasurementList)) || fragmentLength_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist > int64(len(v.InterSystemMeasurementList[fragmentOffset_intersystemmeasurementlist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.InterSystemMeasurementList[fragmentOffset_intersystemmeasurementlist : fragmentOffset_intersystemmeasurementlist+fragmentLength_intersystemmeasurementlist] {
				if err := s21.BridgeInterSystemMeasurementItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding interSystemMeasurementList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding interSystemMeasurementList: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InterSystemMeasurementParameters from APER format.
func (v *InterSystemMeasurementParameters) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *InterSystemMeasurementParameters) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	bb.EnterComponent("InterSystemMeasurementParameters")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterSystemMeasurementParameters")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemMeasurementParameters")
	}
	v.perPadding = padding
	return nil
}
func (v *InterSystemMeasurementParameters) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemMeasurementParameters{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_intersystemmeasurementlist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_measurementduration, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementDuration")
	}
	v.MeasurementDuration = val_measurementduration
	if opt_intersystemmeasurementlist {
		toleranceMark_intersystemmeasurementlist := bb.EnterComponent("InterSystemMeasurementList")
		tmp_intersystemmeasurementlist := make(s21.InterSystemMeasurementList, 0)
		_, errCollection_intersystemmeasurementlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_intersystemmeasurementlist, fragmentLength_intersystemmeasurementlist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist < 0 || fragmentLength_intersystemmeasurementlist > int64(^uint(0)>>1) || fragmentOffset_intersystemmeasurementlist > int64(^uint(0)>>1)-fragmentLength_intersystemmeasurementlist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_intersystemmeasurementlist; i++ {
				var elem s21.InterSystemMeasurementItem
				elementMark := bb.EnterIndex(fragmentOffset_intersystemmeasurementlist + i)
				if err := s21.BridgeInterSystemMeasurementItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementList[%d]", fragmentOffset_intersystemmeasurementlist+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_intersystemmeasurementlist, elem); err != nil {
					return err
				} else {
					tmp_intersystemmeasurementlist = next
				}
			}
			return nil
		})
		if errCollection_intersystemmeasurementlist != nil {
			return runtime.WrapDecodePath(errCollection_intersystemmeasurementlist, "InterSystemMeasurementList")
		}
		v.InterSystemMeasurementList = tmp_intersystemmeasurementlist
		bb.LeaveComponent(toleranceMark_intersystemmeasurementlist)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.InterSystemMeasurementParametersExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.InterSystemMeasurementParametersExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeInterSystemMeasurementParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LoggedMBSFNMDT to APER format.
func (v *LoggedMBSFNMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LoggedMBSFNMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MBSFNResultToLog != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingInterval), 8, false); err != nil {
		return fmt.Errorf("encoding loggingInterval: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LoggingDuration), 6, false); err != nil {
		return fmt.Errorf("encoding loggingDuration: %w", err)
	}
	if v.MBSFNResultToLog != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.MBSFNResultToLog)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnresulttolog, fragmentLength_mbsfnresulttolog int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_mbsfnresulttolog < 0 || fragmentOffset_mbsfnresulttolog > int64(len(v.MBSFNResultToLog)) || fragmentLength_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog > int64(len(v.MBSFNResultToLog[fragmentOffset_mbsfnresulttolog:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.MBSFNResultToLog[fragmentOffset_mbsfnresulttolog : fragmentOffset_mbsfnresulttolog+fragmentLength_mbsfnresulttolog] {
				if err := s22.BridgeMBSFNResultToLogInfoMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding mBSFN-ResultToLog element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding mBSFN-ResultToLog: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LoggedMBSFNMDT from APER format.
func (v *LoggedMBSFNMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *LoggedMBSFNMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	bb.EnterComponent("LoggedMBSFNMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "LoggedMBSFNMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
	}
	v.perPadding = padding
	return nil
}
func (v *LoggedMBSFNMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LoggedMBSFNMDT{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mbsfnresulttolog, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_logginginterval, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "LoggingInterval"})
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingInterval")
	}
	v.LoggingInterval = s00.LoggingInterval(val_logginginterval)
	val_loggingduration, err := aper.DecodeEnumeratedAligned(bb, 6, false, aper.EnumerationSource{KnownExtensions: 0, Path: "LoggingDuration"})
	if err != nil {
		return runtime.WrapDecodePath(err, "LoggingDuration")
	}
	v.LoggingDuration = s00.LoggingDuration(val_loggingduration)
	if opt_mbsfnresulttolog {
		toleranceMark_mbsfnresulttolog := bb.EnterComponent("MBSFNResultToLog")
		tmp_mbsfnresulttolog := make(s22.MBSFNResultToLog, 0)
		_, errCollection_mbsfnresulttolog := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_mbsfnresulttolog, fragmentLength_mbsfnresulttolog int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog < 0 || fragmentLength_mbsfnresulttolog > int64(^uint(0)>>1) || fragmentOffset_mbsfnresulttolog > int64(^uint(0)>>1)-fragmentLength_mbsfnresulttolog {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_mbsfnresulttolog; i++ {
				var elem s22.MBSFNResultToLogInfo
				elementMark := bb.EnterIndex(fragmentOffset_mbsfnresulttolog + i)
				if err := s22.BridgeMBSFNResultToLogInfoMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MBSFNResultToLog[%d]", fragmentOffset_mbsfnresulttolog+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_mbsfnresulttolog, elem); err != nil {
					return err
				} else {
					tmp_mbsfnresulttolog = next
				}
			}
			return nil
		})
		if errCollection_mbsfnresulttolog != nil {
			return runtime.WrapDecodePath(errCollection_mbsfnresulttolog, "MBSFNResultToLog")
		}
		v.MBSFNResultToLog = tmp_mbsfnresulttolog
		bb.LeaveComponent(toleranceMark_mbsfnresulttolog)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.LoggedMBSFNMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.LoggedMBSFNMDTExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeLoggedMBSFNMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PC5QoSParameters to APER format.
func (v *PC5QoSParameters) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PC5QoSParameters) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.Pc5LinkAggregatedBitRates != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.Pc5QoSFlowList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_pc5qosflowlist, fragmentLength_pc5qosflowlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_pc5qosflowlist < 0 || fragmentOffset_pc5qosflowlist > int64(len(v.Pc5QoSFlowList)) || fragmentLength_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist > int64(len(v.Pc5QoSFlowList[fragmentOffset_pc5qosflowlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Pc5QoSFlowList[fragmentOffset_pc5qosflowlist : fragmentOffset_pc5qosflowlist+fragmentLength_pc5qosflowlist] {
			if err := s23.BridgePC5QoSFlowItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding pc5QoSFlowList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding pc5QoSFlowList: %w", err)
	}
	if v.Pc5LinkAggregatedBitRates != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.Pc5LinkAggregatedBitRates), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(10000000000), false); err != nil {
			return fmt.Errorf("encoding pc5LinkAggregatedBitRates: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PC5QoSParameters from APER format.
func (v *PC5QoSParameters) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *PC5QoSParameters) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	bb.EnterComponent("PC5QoSParameters")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	padding, err := aper.CaptureFinalBits(bb, "PC5QoSParameters")
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSParameters")
	}
	v.perPadding = padding
	return nil
}
func (v *PC5QoSParameters) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PC5QoSParameters{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_pc5linkaggregatedbitrates, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_pc5qosflowlist := bb.EnterComponent("Pc5QoSFlowList")
	v.Pc5QoSFlowList = make(s23.PC5QoSFlowList, 0)
	_, errCollection_pc5qosflowlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_pc5qosflowlist, fragmentLength_pc5qosflowlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist < 0 || fragmentLength_pc5qosflowlist > int64(^uint(0)>>1) || fragmentOffset_pc5qosflowlist > int64(^uint(0)>>1)-fragmentLength_pc5qosflowlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_pc5qosflowlist; i++ {
			var elem s23.PC5QoSFlowItem
			elementMark := bb.EnterIndex(fragmentOffset_pc5qosflowlist + i)
			if err := s23.BridgePC5QoSFlowItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Pc5QoSFlowList[%d]", fragmentOffset_pc5qosflowlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Pc5QoSFlowList, elem); err != nil {
				return err
			} else {
				v.Pc5QoSFlowList = next
			}
		}
		return nil
	})
	if errCollection_pc5qosflowlist != nil {
		return runtime.WrapDecodePath(errCollection_pc5qosflowlist, "Pc5QoSFlowList")
	}
	bb.LeaveComponent(toleranceMark_pc5qosflowlist)
	if opt_pc5linkaggregatedbitrates {
		val_pc5linkaggregatedbitrates, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(10000000000), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Pc5LinkAggregatedBitRates")
		}
		tmp_pc5linkaggregatedbitrates := s00.BitRate(val_pc5linkaggregatedbitrates)
		if err := aper.ChargeValue(bb, tmp_pc5linkaggregatedbitrates); err != nil {
			return err
		}
		v.Pc5LinkAggregatedBitRates = (*s00.BitRate)(bb.OwnInt64(int64(tmp_pc5linkaggregatedbitrates)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.PC5QoSParametersExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.PC5QoSParametersExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgePC5QoSParametersExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *InterSystemMeasurementParameters) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemMeasurementParameters", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InterSystemMeasurementParameters", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterSystemMeasurementParameters) WithoutReplay() InterSystemMeasurementParameters {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InterSystemMeasurementParameters
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *IntersystemMeasurementConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "IntersystemMeasurementConfiguration", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "IntersystemMeasurementConfiguration", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v IntersystemMeasurementConfiguration) WithoutReplay() IntersystemMeasurementConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero IntersystemMeasurementConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LoggedMBSFNMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "LoggedMBSFNMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LoggedMBSFNMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LoggedMBSFNMDT) WithoutReplay() LoggedMBSFNMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LoggedMBSFNMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PC5QoSParameters) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "PC5QoSParameters", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PC5QoSParameters", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PC5QoSParameters) WithoutReplay() PC5QoSParameters {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PC5QoSParameters
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *InterSystemMeasurementParameters) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InterSystemMeasurementParameters) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InterSystemMeasurementParameters) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterSystemMeasurementParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *IntersystemMeasurementConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *IntersystemMeasurementConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *IntersystemMeasurementConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("IntersystemMeasurementConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LoggedMBSFNMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LoggedMBSFNMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LoggedMBSFNMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LoggedMBSFNMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PC5QoSParameters) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PC5QoSParameters) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PC5QoSParameters) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PC5QoSParameters.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InterSystemMeasurementParameters) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InterSystemMeasurementParameters")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InterSystemMeasurementParameters) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementParameters")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInterSystemMeasurementParameters(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InterSystemMeasurementParameters")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InterSystemMeasurementParameters")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InterSystemMeasurementParameters) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InterSystemMeasurementParameters")
}
func (v *InterSystemMeasurementParameters) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InterSystemMeasurementParameters")
}
func (v *InterSystemMeasurementParameters) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInterSystemMeasurementParameters(v, &s)
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
func (v *InterSystemMeasurementParameters) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InterSystemMeasurementParameters) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *IntersystemMeasurementConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "IntersystemMeasurementConfiguration")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *IntersystemMeasurementConfiguration) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "IntersystemMeasurementConfiguration")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APIntersystemMeasurementConfiguration(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "IntersystemMeasurementConfiguration")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
}
func (v *IntersystemMeasurementConfiguration) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "IntersystemMeasurementConfiguration")
}
func (v *IntersystemMeasurementConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APIntersystemMeasurementConfiguration(v, &s)
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
func (v *IntersystemMeasurementConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *IntersystemMeasurementConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LoggedMBSFNMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LoggedMBSFNMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LoggedMBSFNMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LoggedMBSFNMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLoggedMBSFNMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LoggedMBSFNMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LoggedMBSFNMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LoggedMBSFNMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LoggedMBSFNMDT")
}
func (v *LoggedMBSFNMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LoggedMBSFNMDT")
}
func (v *LoggedMBSFNMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLoggedMBSFNMDT(v, &s)
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
func (v *LoggedMBSFNMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LoggedMBSFNMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PC5QoSParameters) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PC5QoSParameters")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PC5QoSParameters) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PC5QoSParameters")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPC5QoSParameters(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PC5QoSParameters")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PC5QoSParameters")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PC5QoSParameters) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PC5QoSParameters")
}
func (v *PC5QoSParameters) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PC5QoSParameters")
}
func (v *PC5QoSParameters) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPC5QoSParameters(v, &s)
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
func (v *PC5QoSParameters) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PC5QoSParameters) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InterSystemMeasurementParameters) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterSystemMeasurementParameters")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InterSystemMeasurementParameters
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInterSystemMeasurementParameters(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InterSystemMeasurementParameters{}
		return report, aper.OperationError(err, "InterSystemMeasurementParameters")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterSystemMeasurementParameters")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *IntersystemMeasurementConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "IntersystemMeasurementConfiguration")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded IntersystemMeasurementConfiguration
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APIntersystemMeasurementConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = IntersystemMeasurementConfiguration{}
		return report, aper.OperationError(err, "IntersystemMeasurementConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "IntersystemMeasurementConfiguration")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LoggedMBSFNMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LoggedMBSFNMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LoggedMBSFNMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLoggedMBSFNMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LoggedMBSFNMDT{}
		return report, aper.OperationError(err, "LoggedMBSFNMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LoggedMBSFNMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PC5QoSParameters) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PC5QoSParameters")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PC5QoSParameters
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPC5QoSParameters(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PC5QoSParameters{}
		return report, aper.OperationError(err, "PC5QoSParameters")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PC5QoSParameters")
}

// ENBConfigurationUpdateAcknowledge represents the ASN.1 type ENBConfigurationUpdateAcknowledge (SEQUENCE).
type ENBConfigurationUpdateAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s26.ENBConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBConfigurationUpdateFailure represents the ASN.1 type ENBConfigurationUpdateFailure (SEQUENCE).
type ENBConfigurationUpdateFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s26.ENBConfigurationUpdateFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBStatusTransfer represents the ASN.1 type ENBStatusTransfer (SEQUENCE).
type ENBStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s25.ENBStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ENBConfigurationUpdateAcknowledge to APER format.
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBConfigurationUpdateAcknowledge from APER format.
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	bb.EnterComponent("ENBConfigurationUpdateAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	v.perPadding = padding
	return nil
}
func (v *ENBConfigurationUpdateAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateAcknowledge{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.ENBConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.ENBConfigurationUpdateAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeENBConfigurationUpdateAcknowledgeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENBConfigurationUpdateFailure to APER format.
func (v *ENBConfigurationUpdateFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBConfigurationUpdateFailure from APER format.
func (v *ENBConfigurationUpdateFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBConfigurationUpdateFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	bb.EnterComponent("ENBConfigurationUpdateFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateFailure")
	}
	v.perPadding = padding
	return nil
}
func (v *ENBConfigurationUpdateFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s26.ENBConfigurationUpdateFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s26.ENBConfigurationUpdateFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s26.BridgeENBConfigurationUpdateFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENBStatusTransfer to APER format.
func (v *ENBStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s25.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBStatusTransfer from APER format.
func (v *ENBStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	bb.EnterComponent("ENBStatusTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransfer")
	}
	v.perPadding = padding
	return nil
}
func (v *ENBStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s25.ENBStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s25.ENBStatusTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s25.BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ENBConfigurationUpdateAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdateAcknowledge) WithoutReplay() ENBConfigurationUpdateAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdateAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBConfigurationUpdateFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdateFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdateFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdateFailure) WithoutReplay() ENBConfigurationUpdateFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdateFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBStatusTransfer) WithoutReplay() ENBStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdateAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdateFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdateFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdateFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBConfigurationUpdateAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationUpdateAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationUpdateAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationUpdateAcknowledge(v, &s)
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
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationUpdateAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBConfigurationUpdateFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBConfigurationUpdateFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBConfigurationUpdateFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBConfigurationUpdateFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func (v *ENBConfigurationUpdateFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func (v *ENBConfigurationUpdateFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBConfigurationUpdateFailure(v, &s)
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
func (v *ENBConfigurationUpdateFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBConfigurationUpdateFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBStatusTransfer")
}
func (v *ENBStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBStatusTransfer")
}
func (v *ENBStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBStatusTransfer(v, &s)
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
func (v *ENBStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationUpdateAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationUpdateAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationUpdateAcknowledge{}
		return report, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdateAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBConfigurationUpdateFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBConfigurationUpdateFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBConfigurationUpdateFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBConfigurationUpdateFailure{}
		return report, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdateFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBStatusTransfer{}
		return report, aper.OperationError(err, "ENBStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBStatusTransfer")
}

// SONtransferRequestContainer represents the ASN.1 CHOICE type SONtransferRequestContainer.
type SONtransferRequestContainer struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding                        `json:"-"`
	perOpenTypePadding              aper.CompletePadding                        `json:"-"`
	UnknownExtension                *aper.ChoiceExtension                       `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *struct{}                                   `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          *MultiCellLoadReportingRequest              `json:"MultiCellLoadReporting,omitempty"`
	EventTriggeredCellLoadReporting *s21.EventTriggeredCellLoadReportingRequest `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *s25.HOReport                               `json:"HOReporting,omitempty"`
	EutranCellActivation            *s26.CellActivationRequest                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *CellStateIndication                        `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *s24.FailureEventReport                     `json:"FailureEventReporting,omitempty"`
}

// SONtransferResponseContainer represents the ASN.1 CHOICE type SONtransferResponseContainer.
type SONtransferResponseContainer struct {
	replay                          aper.Snapshot
	stream                          aper.WireSpan
	received                        bool
	withoutReplay                   bool
	receivedAbsolute                bool
	receivedBytes                   aper.WireSpan
	receivedLocation                aper.Location
	Choice                          int
	perPadding                      aper.CompletePadding                         `json:"-"`
	perOpenTypePadding              aper.CompletePadding                         `json:"-"`
	UnknownExtension                *aper.ChoiceExtension                        `json:"UnknownExtension,omitempty"`
	CellLoadReporting               *s21.CellLoadReportingResponse               `json:"CellLoadReporting,omitempty"`
	MultiCellLoadReporting          s22.MultiCellLoadReportingResponse           `json:"MultiCellLoadReporting,omitzero"`
	EventTriggeredCellLoadReporting *s21.EventTriggeredCellLoadReportingResponse `json:"EventTriggeredCellLoadReporting,omitempty"`
	HOReporting                     *struct{}                                    `json:"HOReporting,omitempty"`
	EutranCellActivation            *s25.CellActivationResponse                  `json:"EutranCellActivation,omitempty"`
	EnergySavingsIndication         *struct{}                                    `json:"EnergySavingsIndication,omitempty"`
	FailureEventReporting           *struct{}                                    `json:"FailureEventReporting,omitempty"`
}

// MultiCellLoadReportingRequest represents the ASN.1 type MultiCellLoadReportingRequest (SEQUENCE).
type MultiCellLoadReportingRequest struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	RequestedCellList      s23.RequestedCellList  `asn1:"tag:0,context,implicit"`
	requestedCellListIndef bool                   `asn1:"-" json:"-"`
	extCount               int64                  `asn1:"-" json:"-"`
	extPresent             []bool                 `asn1:"-" json:"-"`
	extData                [][]byte               `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// CellStateIndication represents the ASN.1 type CellStateIndication (SEQUENCE).
type CellStateIndication struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	NotificationCellList      s23.NotificationCellList `asn1:"tag:0,context,implicit"`
	notificationCellListIndef bool                     `asn1:"-" json:"-"`
	extCount                  int64                    `asn1:"-" json:"-"`
	extPresent                []bool                   `asn1:"-" json:"-"`
	extData                   [][]byte                 `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding        `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding   `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// MarshalAPER encodes SONtransferRequestContainer to APER format.
func (v *SONtransferRequestContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferRequestContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferRequestContainer:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferRequestContainer:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferRequestContainer:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONtransferRequestContainer:", v.Choice)
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
		case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
			if v.MultiCellLoadReporting == nil {
				return fmt.Errorf("choice alternative multiCellLoadReporting is nil")
			}
			if err := v.MultiCellLoadReporting.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := s21.BridgeEventTriggeredCellLoadReportingRequestMethodMarshalAPERTo(v.EventTriggeredCellLoadReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceHOReporting:
			if v.HOReporting == nil {
				return fmt.Errorf("choice alternative hOReporting is nil")
			}
			if err := s25.BridgeHOReportMethodMarshalAPERTo(v.HOReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding hOReporting: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := s26.BridgeCellActivationRequestMethodMarshalAPERTo(v.EutranCellActivation, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
			if v.EnergySavingsIndication == nil {
				return fmt.Errorf("choice alternative energySavingsIndication is nil")
			}
			if err := v.EnergySavingsIndication.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding energySavingsIndication: %w", err)
			}
		case s00.SONtransferRequestContainerChoiceFailureEventReporting:
			if v.FailureEventReporting == nil {
				return fmt.Errorf("choice alternative failureEventReporting is nil")
			}
			if err := s24.BridgeFailureEventReportMethodMarshalAPERTo(v.FailureEventReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding failureEventReporting: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONtransferRequestContainer extension choice %d", v.Choice)
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
	switch v.Choice {
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
	default:
		return fmt.Errorf("unknown SONtransferRequestContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferRequestContainer from APER format.
func (v *SONtransferRequestContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SONtransferRequestContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	bb.EnterComponent("SONtransferRequestContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferRequestContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferRequestContainer")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferRequestContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferRequestContainer{}
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
		case s00.SONtransferRequestContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			toleranceMark_multicellloadreporting := inner.EnterComponent("MultiCellLoadReporting")
			var dec_multicellloadreporting MultiCellLoadReportingRequest
			if err := dec_multicellloadreporting.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "MultiCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_multicellloadreporting); err != nil {
				return err
			}
			v.MultiCellLoadReporting = &dec_multicellloadreporting
			inner.LeaveComponent(toleranceMark_multicellloadreporting)
		case s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			toleranceMark_eventtriggeredcellloadreporting := inner.EnterComponent("EventTriggeredCellLoadReporting")
			var dec_eventtriggeredcellloadreporting s21.EventTriggeredCellLoadReportingRequest
			if err := s21.BridgeEventTriggeredCellLoadReportingRequestMethodUnmarshalAPERFrom(&dec_eventtriggeredcellloadreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
			inner.LeaveComponent(toleranceMark_eventtriggeredcellloadreporting)
		case s00.SONtransferRequestContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			toleranceMark_horeporting := inner.EnterComponent("HOReporting")
			var dec_horeporting s25.HOReport
			if err := s25.BridgeHOReportMethodUnmarshalAPERFrom(&dec_horeporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "HOReporting")
			}
			if err := aper.ChargeValue(inner, dec_horeporting); err != nil {
				return err
			}
			v.HOReporting = &dec_horeporting
			inner.LeaveComponent(toleranceMark_horeporting)
		case s00.SONtransferRequestContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			toleranceMark_eutrancellactivation := inner.EnterComponent("EutranCellActivation")
			var dec_eutrancellactivation s26.CellActivationRequest
			if err := s26.BridgeCellActivationRequestMethodUnmarshalAPERFrom(&dec_eutrancellactivation, inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			if err := aper.ChargeValue(inner, dec_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = &dec_eutrancellactivation
			inner.LeaveComponent(toleranceMark_eutrancellactivation)
		case s00.SONtransferRequestContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			toleranceMark_energysavingsindication := inner.EnterComponent("EnergySavingsIndication")
			var dec_energysavingsindication CellStateIndication
			if err := dec_energysavingsindication.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "EnergySavingsIndication")
			}
			if err := aper.ChargeValue(inner, dec_energysavingsindication); err != nil {
				return err
			}
			v.EnergySavingsIndication = &dec_energysavingsindication
			inner.LeaveComponent(toleranceMark_energysavingsindication)
		case s00.SONtransferRequestContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			toleranceMark_failureeventreporting := inner.EnterComponent("FailureEventReporting")
			var dec_failureeventreporting s24.FailureEventReport
			if err := s24.BridgeFailureEventReportMethodUnmarshalAPERFrom(&dec_failureeventreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "FailureEventReporting")
			}
			if err := aper.ChargeValue(inner, dec_failureeventreporting); err != nil {
				return err
			}
			v.FailureEventReporting = &dec_failureeventreporting
			inner.LeaveComponent(toleranceMark_failureeventreporting)
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
	case s00.SONtransferRequestContainerChoiceCellLoadReporting:
		v.CellLoadReporting = new(struct{})
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes SONtransferResponseContainer to APER format.
func (v *SONtransferResponseContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONtransferResponseContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONtransferResponseContainer:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONtransferResponseContainer:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONtransferResponseContainer:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "SONtransferResponseContainer:", v.Choice)
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
		case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
			if err := aper.EncodeCollection(inner, int64(len(v.MultiCellLoadReporting)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_multicellloadreporting < 0 || fragmentOffset_multicellloadreporting > int64(len(v.MultiCellLoadReporting)) || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(len(v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting:])) {
					return fmt.Errorf("collection fragment outside value")
				}
				for _, elem := range v.MultiCellLoadReporting[fragmentOffset_multicellloadreporting : fragmentOffset_multicellloadreporting+fragmentLength_multicellloadreporting] {
					if err := s22.BridgeMultiCellLoadReportingResponseItemMethodMarshalAPERTo(&elem, inner, len(fresh) != 0 && fresh[0]); err != nil {
						return fmt.Errorf("encoding multiCellLoadReporting element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding multiCellLoadReporting: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			if v.EventTriggeredCellLoadReporting == nil {
				return fmt.Errorf("choice alternative eventTriggeredCellLoadReporting is nil")
			}
			if err := s21.BridgeEventTriggeredCellLoadReportingResponseMethodMarshalAPERTo(v.EventTriggeredCellLoadReporting, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eventTriggeredCellLoadReporting: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceHOReporting:
		case s00.SONtransferResponseContainerChoiceEutranCellActivation:
			if v.EutranCellActivation == nil {
				return fmt.Errorf("choice alternative eutranCellActivation is nil")
			}
			if err := s25.BridgeCellActivationResponseMethodMarshalAPERTo(v.EutranCellActivation, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding eutranCellActivation: %w", err)
			}
		case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
		case s00.SONtransferResponseContainerChoiceFailureEventReporting:
		default:
			return fmt.Errorf("unknown SONtransferResponseContainer extension choice %d", v.Choice)
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
	switch v.Choice {
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		if v.CellLoadReporting == nil {
			return fmt.Errorf("choice alternative cellLoadReporting is nil")
		}
		if err := s21.BridgeCellLoadReportingResponseMethodMarshalAPERTo(v.CellLoadReporting, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cellLoadReporting: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONtransferResponseContainer choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONtransferResponseContainer from APER format.
func (v *SONtransferResponseContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *SONtransferResponseContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	bb.EnterComponent("SONtransferResponseContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONtransferResponseContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONtransferResponseContainer")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONtransferResponseContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONtransferResponseContainer{}
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
		case s00.SONtransferResponseContainerChoiceMultiCellLoadReporting:
			extensionPath = "MultiCellLoadReporting"
			toleranceMark_multicellloadreporting := inner.EnterComponent("MultiCellLoadReporting")
			tmp_multicellloadreporting := make(s22.MultiCellLoadReportingResponse, 0)
			_, errCollection_multicellloadreporting := aper.DecodeCollection(inner, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_multicellloadreporting, fragmentLength_multicellloadreporting int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
				if fragmentOffset_multicellloadreporting < 0 || fragmentLength_multicellloadreporting < 0 || fragmentLength_multicellloadreporting > int64(^uint(0)>>1) || fragmentOffset_multicellloadreporting > int64(^uint(0)>>1)-fragmentLength_multicellloadreporting {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_multicellloadreporting; i++ {
					var elem s22.MultiCellLoadReportingResponseItem
					elementMark := inner.EnterIndex(fragmentOffset_multicellloadreporting + i)
					if err := s22.BridgeMultiCellLoadReportingResponseItemMethodUnmarshalAPERFrom(&elem, inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReporting[%d]", fragmentOffset_multicellloadreporting+i))
					}
					inner.LeaveComponent(elementMark)
					if next, err := aper.AppendValues(inner, tmp_multicellloadreporting, elem); err != nil {
						return err
					} else {
						tmp_multicellloadreporting = next
					}
				}
				return nil
			})
			if errCollection_multicellloadreporting != nil {
				return runtime.WrapDecodePath(errCollection_multicellloadreporting, "MultiCellLoadReporting")
			}
			v.MultiCellLoadReporting = tmp_multicellloadreporting
			inner.LeaveComponent(toleranceMark_multicellloadreporting)
		case s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting:
			extensionPath = "EventTriggeredCellLoadReporting"
			toleranceMark_eventtriggeredcellloadreporting := inner.EnterComponent("EventTriggeredCellLoadReporting")
			var dec_eventtriggeredcellloadreporting s21.EventTriggeredCellLoadReportingResponse
			if err := s21.BridgeEventTriggeredCellLoadReportingResponseMethodUnmarshalAPERFrom(&dec_eventtriggeredcellloadreporting, inner); err != nil {
				return runtime.WrapDecodePath(err, "EventTriggeredCellLoadReporting")
			}
			if err := aper.ChargeValue(inner, dec_eventtriggeredcellloadreporting); err != nil {
				return err
			}
			v.EventTriggeredCellLoadReporting = &dec_eventtriggeredcellloadreporting
			inner.LeaveComponent(toleranceMark_eventtriggeredcellloadreporting)
		case s00.SONtransferResponseContainerChoiceHOReporting:
			extensionPath = "HOReporting"
			v.HOReporting = new(struct{})
		case s00.SONtransferResponseContainerChoiceEutranCellActivation:
			extensionPath = "EutranCellActivation"
			toleranceMark_eutrancellactivation := inner.EnterComponent("EutranCellActivation")
			var dec_eutrancellactivation s25.CellActivationResponse
			if err := s25.BridgeCellActivationResponseMethodUnmarshalAPERFrom(&dec_eutrancellactivation, inner); err != nil {
				return runtime.WrapDecodePath(err, "EutranCellActivation")
			}
			if err := aper.ChargeValue(inner, dec_eutrancellactivation); err != nil {
				return err
			}
			v.EutranCellActivation = &dec_eutrancellactivation
			inner.LeaveComponent(toleranceMark_eutrancellactivation)
		case s00.SONtransferResponseContainerChoiceEnergySavingsIndication:
			extensionPath = "EnergySavingsIndication"
			v.EnergySavingsIndication = new(struct{})
		case s00.SONtransferResponseContainerChoiceFailureEventReporting:
			extensionPath = "FailureEventReporting"
			v.FailureEventReporting = new(struct{})
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
	case s00.SONtransferResponseContainerChoiceCellLoadReporting:
		toleranceMark_cellloadreporting := bb.EnterComponent("CellLoadReporting")
		var dec_cellloadreporting s21.CellLoadReportingResponse
		if err := s21.BridgeCellLoadReportingResponseMethodUnmarshalAPERFrom(&dec_cellloadreporting, bb); err != nil {
			return runtime.WrapDecodePath(err, "CellLoadReporting")
		}
		if err := aper.ChargeValue(bb, dec_cellloadreporting); err != nil {
			return err
		}
		v.CellLoadReporting = &dec_cellloadreporting
		bb.LeaveComponent(toleranceMark_cellloadreporting)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MultiCellLoadReportingRequest to APER format.
func (v *MultiCellLoadReportingRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MultiCellLoadReportingRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.RequestedCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_requestedcelllist < 0 || fragmentOffset_requestedcelllist > int64(len(v.RequestedCellList)) || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(len(v.RequestedCellList[fragmentOffset_requestedcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.RequestedCellList[fragmentOffset_requestedcelllist : fragmentOffset_requestedcelllist+fragmentLength_requestedcelllist] {
			if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding requestedCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding requestedCellList: %w", err)
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

// UnmarshalAPER decodes MultiCellLoadReportingRequest from APER format.
func (v *MultiCellLoadReportingRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MultiCellLoadReportingRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	bb.EnterComponent("MultiCellLoadReportingRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "MultiCellLoadReportingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "MultiCellLoadReportingRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *MultiCellLoadReportingRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MultiCellLoadReportingRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_requestedcelllist := bb.EnterComponent("RequestedCellList")
	v.RequestedCellList = make(s23.RequestedCellList, 0)
	_, errCollection_requestedcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_requestedcelllist, fragmentLength_requestedcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_requestedcelllist < 0 || fragmentLength_requestedcelllist < 0 || fragmentLength_requestedcelllist > int64(^uint(0)>>1) || fragmentOffset_requestedcelllist > int64(^uint(0)>>1)-fragmentLength_requestedcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_requestedcelllist; i++ {
			var elem s21.IRATCellID
			elementMark := bb.EnterIndex(fragmentOffset_requestedcelllist + i)
			if err := s21.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedCellList[%d]", fragmentOffset_requestedcelllist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.RequestedCellList, elem); err != nil {
				return err
			} else {
				v.RequestedCellList = next
			}
		}
		return nil
	})
	if errCollection_requestedcelllist != nil {
		return runtime.WrapDecodePath(errCollection_requestedcelllist, "RequestedCellList")
	}
	bb.LeaveComponent(toleranceMark_requestedcelllist)
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

// MarshalAPER encodes CellStateIndication to APER format.
func (v *CellStateIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellStateIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.NotificationCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_notificationcelllist < 0 || fragmentOffset_notificationcelllist > int64(len(v.NotificationCellList)) || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(len(v.NotificationCellList[fragmentOffset_notificationcelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.NotificationCellList[fragmentOffset_notificationcelllist : fragmentOffset_notificationcelllist+fragmentLength_notificationcelllist] {
			if err := s23.BridgeNotificationCellListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding notificationCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding notificationCellList: %w", err)
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

// UnmarshalAPER decodes CellStateIndication from APER format.
func (v *CellStateIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellStateIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	bb.EnterComponent("CellStateIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellStateIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellStateIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *CellStateIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellStateIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_notificationcelllist := bb.EnterComponent("NotificationCellList")
	v.NotificationCellList = make(s23.NotificationCellList, 0)
	_, errCollection_notificationcelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_notificationcelllist, fragmentLength_notificationcelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_notificationcelllist < 0 || fragmentLength_notificationcelllist < 0 || fragmentLength_notificationcelllist > int64(^uint(0)>>1) || fragmentOffset_notificationcelllist > int64(^uint(0)>>1)-fragmentLength_notificationcelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_notificationcelllist; i++ {
			var elem s23.NotificationCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_notificationcelllist + i)
			if err := s23.BridgeNotificationCellListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("NotificationCellList[%d]", fragmentOffset_notificationcelllist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.NotificationCellList, elem); err != nil {
				return err
			} else {
				v.NotificationCellList = next
			}
		}
		return nil
	})
	if errCollection_notificationcelllist != nil {
		return runtime.WrapDecodePath(errCollection_notificationcelllist, "NotificationCellList")
	}
	bb.LeaveComponent(toleranceMark_notificationcelllist)
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
func (v *CellStateIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellStateIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellStateIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellStateIndication) WithoutReplay() CellStateIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellStateIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MultiCellLoadReportingRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MultiCellLoadReportingRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MultiCellLoadReportingRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MultiCellLoadReportingRequest) WithoutReplay() MultiCellLoadReportingRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MultiCellLoadReportingRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferRequestContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferRequestContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferRequestContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferRequestContainer) WithoutReplay() SONtransferRequestContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferRequestContainer
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONtransferResponseContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONtransferResponseContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONtransferResponseContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONtransferResponseContainer) WithoutReplay() SONtransferResponseContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONtransferResponseContainer
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellStateIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellStateIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellStateIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellStateIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MultiCellLoadReportingRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MultiCellLoadReportingRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MultiCellLoadReportingRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MultiCellLoadReportingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellStateIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellStateIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellStateIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellStateIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellStateIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellStateIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellStateIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellStateIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellStateIndication")
}
func (v *CellStateIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellStateIndication")
}
func (v *CellStateIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellStateIndication(v, &s)
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
func (v *CellStateIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellStateIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MultiCellLoadReportingRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MultiCellLoadReportingRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MultiCellLoadReportingRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMultiCellLoadReportingRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MultiCellLoadReportingRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MultiCellLoadReportingRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
}
func (v *MultiCellLoadReportingRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MultiCellLoadReportingRequest")
}
func (v *MultiCellLoadReportingRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMultiCellLoadReportingRequest(v, &s)
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
func (v *MultiCellLoadReportingRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MultiCellLoadReportingRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONtransferRequestContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferRequestContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferRequestContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferRequestContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferRequestContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferRequestContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferRequestContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferRequestContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferRequestContainer")
}
func (v *SONtransferRequestContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferRequestContainer")
}
func (v *SONtransferRequestContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferRequestContainer(v, &s)
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
func (v *SONtransferRequestContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferRequestContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONtransferResponseContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONtransferResponseContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONtransferResponseContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONtransferResponseContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONtransferResponseContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONtransferResponseContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONtransferResponseContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONtransferResponseContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONtransferResponseContainer")
}
func (v *SONtransferResponseContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONtransferResponseContainer")
}
func (v *SONtransferResponseContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONtransferResponseContainer(v, &s)
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
func (v *SONtransferResponseContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONtransferResponseContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellStateIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellStateIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellStateIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellStateIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellStateIndication{}
		return report, aper.OperationError(err, "CellStateIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellStateIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MultiCellLoadReportingRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MultiCellLoadReportingRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MultiCellLoadReportingRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMultiCellLoadReportingRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MultiCellLoadReportingRequest{}
		return report, aper.OperationError(err, "MultiCellLoadReportingRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MultiCellLoadReportingRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferRequestContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferRequestContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferRequestContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferRequestContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferRequestContainer{}
		return report, aper.OperationError(err, "SONtransferRequestContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferRequestContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONtransferResponseContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONtransferResponseContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONtransferResponseContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONtransferResponseContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONtransferResponseContainer{}
		return report, aper.OperationError(err, "SONtransferResponseContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONtransferResponseContainer")
}

// NewSONtransferRequestContainerUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferRequestContainerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferRequestContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	value := SONtransferRequestContainer{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferRequestContainer{}, aper.OperationError(err, "SONtransferRequestContainerUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferRequestContainerUnknownExtension")
}

// NewSONtransferResponseContainerUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONtransferResponseContainerUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONtransferResponseContainer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	value := SONtransferResponseContainer{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONtransferResponseContainer{}, aper.OperationError(err, "SONtransferResponseContainerUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONtransferResponseContainerUnknownExtension")
}

type MDTModeExtensionIEIEValue struct {
	id                s00.ProtocolIEID
	received          aper.WireSpan
	replay            aper.Snapshot
	opaque            aper.OpaqueOpenType
	isOpaque          bool
	rowLoggedMBSFNMDT *LoggedMBSFNMDT
}

func (v MDTModeExtensionIEIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(197):
		return v.rowLoggedMBSFNMDT != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MDTModeExtensionIEIEValue and reports whether the opaque alternative is selected.
func (v *MDTModeExtensionIEIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MDTModeExtensionIEIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE"}}
}
func (MDTModeExtensionIEIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(197):
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

// AsLoggedMBSFNMDT returns the selected LoggedMBSFNMDT value of MDTModeExtensionIEIEValue and reports whether that alternative is active.
func (v *MDTModeExtensionIEIEValue) AsLoggedMBSFNMDT() (*LoggedMBSFNMDT, bool) {
	if v == nil || v.id != s00.ProtocolIEID(197) || v.rowLoggedMBSFNMDT == nil {
		return nil, false
	}
	return v.rowLoggedMBSFNMDT, true
}
func (v MDTModeExtensionIEIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MDTModeExtensionIEIEValue, error) {
	out := MDTModeExtensionIEIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(197):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value LoggedMBSFNMDT
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "LoggedMBSFNMDT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LoggedMBSFNMDT")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowLoggedMBSFNMDT = &value
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
func (v MDTModeExtensionIEIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MDTModeExtensionIEIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(197):
		if v.rowLoggedMBSFNMDT == nil {
			return nil, fmt.Errorf("%s missing value", "MDTMode-ExtensionIE.id-LoggedMBSFNMDT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowLoggedMBSFNMDT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MDTModeExtensionIEIEValue:", v.id)
	}
}

type UERadioCapabilityIDMappingResponseIEValue struct {
	id                        s00.ProtocolIEID
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    aper.OpaqueOpenType
	isOpaque                  bool
	rowUERadioCapabilityID    *s00.UERadioCapabilityID
	rowUERadioCapability      *s00.UERadioCapability
	rowCriticalityDiagnostics *s26.CriticalityDiagnostics
}

func (v UERadioCapabilityIDMappingResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UERadioCapabilityIDMappingResponseIEValue and reports whether the opaque alternative is selected.
func (v *UERadioCapabilityIDMappingResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UERadioCapabilityIDMappingResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs"}}
}
func (UERadioCapabilityIDMappingResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of UERadioCapabilityIDMappingResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityIDMappingResponseIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsUERadioCapability returns the selected UERadioCapability value of UERadioCapabilityIDMappingResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityIDMappingResponseIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of UERadioCapabilityIDMappingResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityIDMappingResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UERadioCapabilityIDMappingResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UERadioCapabilityIDMappingResponseIEValue, error) {
	out := UERadioCapabilityIDMappingResponseIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(314):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityID, error) {
			var v struct{ Value s00.UERadioCapabilityID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityID(val_value)
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
		out.rowUERadioCapabilityID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(74):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapability, error) {
			var v struct{ Value s00.UERadioCapability }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapability(val_value)
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
		out.rowUERadioCapability = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
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
func (v UERadioCapabilityIDMappingResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UERadioCapabilityIDMappingResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-UERadioCapabilityID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapabilityID }{Value: value}
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
		})(*v.rowUERadioCapabilityID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-UERadioCapability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapability }{Value: value}
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
		})(*v.rowUERadioCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityIDMappingResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UERadioCapabilityIDMappingResponseIEValue:", v.id)
	}
}

type UERadioCapabilityMatchResponseIEValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowMMEUES1APID                *s00.MMEUES1APID
	rowENBUES1APID                *s00.ENBUES1APID
	rowVoiceSupportMatchIndicator *s00.VoiceSupportMatchIndicator
	rowCriticalityDiagnostics     *s26.CriticalityDiagnostics
}

func (v UERadioCapabilityMatchResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(169):
		return v.rowVoiceSupportMatchIndicator != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UERadioCapabilityMatchResponseIEValue and reports whether the opaque alternative is selected.
func (v *UERadioCapabilityMatchResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UERadioCapabilityMatchResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs"}}
}
func (UERadioCapabilityMatchResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(169):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UERadioCapabilityMatchResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityMatchResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UERadioCapabilityMatchResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityMatchResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsVoiceSupportMatchIndicator returns the selected VoiceSupportMatchIndicator value of UERadioCapabilityMatchResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityMatchResponseIEValue) AsVoiceSupportMatchIndicator() (*s00.VoiceSupportMatchIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(169) || v.rowVoiceSupportMatchIndicator == nil {
		return nil, false
	}
	return v.rowVoiceSupportMatchIndicator, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of UERadioCapabilityMatchResponseIEValue and reports whether that alternative is active.
func (v *UERadioCapabilityMatchResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v UERadioCapabilityMatchResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UERadioCapabilityMatchResponseIEValue, error) {
	out := UERadioCapabilityMatchResponseIEValue{id: id}
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
	case s00.ProtocolIEID(169):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "VoiceSupportMatchIndicator"})
		value := s00.VoiceSupportMatchIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "VoiceSupportMatchIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowVoiceSupportMatchIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
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
func (v UERadioCapabilityMatchResponseIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UERadioCapabilityMatchResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(169):
		if v.rowVoiceSupportMatchIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-VoiceSupportMatchIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowVoiceSupportMatchIndicator), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UERadioCapabilityMatchResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UERadioCapabilityMatchResponseIEValue:", v.id)
	}
}

type MDTModeExtensionIETable struct{}

func MDTModeExtensionIE() MDTModeExtensionIETable { return MDTModeExtensionIETable{} }

// ID returns the ASN.1 object-set identity of MDTModeExtensionIETable.
func (MDTModeExtensionIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MDTModeExtensionIETable.
func (MDTModeExtensionIETable) Table() s00.MDTModeExtensionIEIEValueIETable {
	return func() s00.MDTModeExtensionIEIEValueIETable {
		sealed := s00.MDTModeExtensionIEIEValueIETable{}
		*s00.BridgeMDTModeExtensionIEIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MDTModeExtensionIETable) infoLoggedMBSFNMDT() s00.FieldInfo {
	return s00.FieldInfo{Table: MDTModeExtensionIE().ID(), ID: s00.ProtocolIEID(197), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LoggedMBSFNMDT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTMode-ExtensionIE", Row: "id-LoggedMBSFNMDT"}}}
}

// LoggedMBSFNMDT returns the typed binding for the LoggedMBSFNMDT row of MDTModeExtensionIETable.
func (t MDTModeExtensionIETable) LoggedMBSFNMDT() MDTModeExtensionIELoggedMBSFNMDTIEBinding {
	return MDTModeExtensionIELoggedMBSFNMDTIEBinding{info: t.infoLoggedMBSFNMDT(), codec: LoggedMBSFNMDTValueCodec{path: "LoggedMBSFNMDT",
		decode: func(data []byte, options aper.DecodeState) (LoggedMBSFNMDT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty LoggedMBSFNMDT
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LoggedMBSFNMDT")
			var zero MDTModeExtensionIEIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(197), raw)
			if err != nil {
				var empty LoggedMBSFNMDT
				return empty, runtime.WrapDecodePath(err, "LoggedMBSFNMDT")
			}
			value, ok := decoded.AsLoggedMBSFNMDT()
			if !ok {
				var empty LoggedMBSFNMDT
				return empty, fmt.Errorf("binding MDTMode-ExtensionIE.id-LoggedMBSFNMDT: no selected value")
			}
			return *value, nil
		},
		encode: func(value LoggedMBSFNMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MDTModeExtensionIEIEValue{id: s00.ProtocolIEID(197), rowLoggedMBSFNMDT: &value}).encodeFresh(fresh, budget)
		}, capture: func(v LoggedMBSFNMDT, options aper.DecodeState) (LoggedMBSFNMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APLoggedMBSFNMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v LoggedMBSFNMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLoggedMBSFNMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggedMBSFNMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value LoggedMBSFNMDT) MDTModeExtensionIEIEValue {
		return MDTModeExtensionIEIEValue{id: s00.ProtocolIEID(197), rowLoggedMBSFNMDT: &value}
	}, get: func(value *MDTModeExtensionIEIEValue) (*LoggedMBSFNMDT, bool) { return value.AsLoggedMBSFNMDT() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MDTModeExtensionIETable.
func (t MDTModeExtensionIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MDTModeExtensionIEIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(197):
		return MDTModeExtensionIEIEField{}, aper.OperationError(fmt.Errorf("known IE id-LoggedMBSFNMDT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MDTModeExtensionIEIEField{}, aper.OperationError(err, "Opaque")
		}
		return MDTModeExtensionIEIEField{Id: id, Criticality: criticality, Value: MDTModeExtensionIEIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextResumeFailureIETable struct{}

func UEContextResumeFailureIEs() UEContextResumeFailureIETable {
	return UEContextResumeFailureIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextResumeFailureIETable.
func (UEContextResumeFailureIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextResumeFailureIETable.
func (UEContextResumeFailureIETable) Table() s00.UEContextResumeFailureIEValueIETable {
	return func() s00.UEContextResumeFailureIEValueIETable {
		sealed := s00.UEContextResumeFailureIEValueIETable{}
		*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextResumeFailureIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextResumeFailureIETable.
func (t UEContextResumeFailureIETable) MMEUES1APID() UEContextResumeFailureMMEUES1APIDIEBinding {
	return UEContextResumeFailureMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero s27.UEContextResumeFailureIEValue
			decoded, err := s27.BridgeUEContextResumeFailureIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s27.BridgeUEContextResumeFailureIEValueMethodEncodeFresh((func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()), fresh, budget)
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
		inject: func(value s00.MMEUES1APID) s27.UEContextResumeFailureIEValue {
			return func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *s27.UEContextResumeFailureIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextResumeFailureIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextResumeFailureIETable.
func (t UEContextResumeFailureIETable) ENBUES1APID() s27.UEContextResumeFailureENBUES1APIDIEBinding {
	return func() s27.UEContextResumeFailureENBUES1APIDIEBinding {
		sealed := s27.UEContextResumeFailureENBUES1APIDIEBinding{}
		*s27.BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s27.BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s27.UEContextResumeFailureIEValue
				decoded, err := s27.BridgeUEContextResumeFailureIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s27.BridgeUEContextResumeFailureIEValueMethodEncodeFresh((func() s27.UEContextResumeFailureIEValue {
					sealed := s27.UEContextResumeFailureIEValue{}
					*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s27.BridgeUEContextResumeFailureIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s27.BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s27.UEContextResumeFailureIEValue {
			return func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s27.BridgeUEContextResumeFailureENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s27.UEContextResumeFailureIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (UEContextResumeFailureIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of UEContextResumeFailureIETable.
func (t UEContextResumeFailureIETable) Cause() s27.UEContextResumeFailureCauseIEBinding {
	return func() s27.UEContextResumeFailureCauseIEBinding {
		sealed := s27.UEContextResumeFailureCauseIEBinding{}
		*s27.BridgeUEContextResumeFailureCauseIEBindingFieldInfo(&sealed) = t.infoCause()
		*s27.BridgeUEContextResumeFailureCauseIEBindingFieldCodec(&sealed) = func() s17.CauseValueCodec {
			sealed := s17.CauseValueCodec{}
			*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
			*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.Cause
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cause")
				var zero s27.UEContextResumeFailureIEValue
				decoded, err := s27.BridgeUEContextResumeFailureIEValueMethodDecode(zero, s00.ProtocolIEID(2), raw)
				if err != nil {
					var empty s17.Cause
					return empty, runtime.WrapDecodePath(err, "Cause")
				}
				value, ok := decoded.AsCause()
				if !ok {
					var empty s17.Cause
					return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-Cause: no selected value")
				}
				return *value, nil
			}
			*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s27.BridgeUEContextResumeFailureIEValueMethodEncodeFresh((func() s27.UEContextResumeFailureIEValue {
					sealed := s27.UEContextResumeFailureIEValue{}
					*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
					*s27.BridgeUEContextResumeFailureIEValueFieldRowCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s27.BridgeUEContextResumeFailureCauseIEBindingFieldInject(&sealed) = func(value s17.Cause) s27.UEContextResumeFailureIEValue {
			return func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowCause(&sealed) = &value
				return sealed
			}()
		}
		*s27.BridgeUEContextResumeFailureCauseIEBindingFieldGet(&sealed) = func(value *s27.UEContextResumeFailureIEValue) (*s17.Cause, bool) { return value.AsCause() }
		return sealed
	}()
}
func (UEContextResumeFailureIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeFailureIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeFailureIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UEContextResumeFailureIETable.
func (t UEContextResumeFailureIETable) CriticalityDiagnostics() s27.UEContextResumeFailureCriticalityDiagnosticsIEBinding {
	return func() s27.UEContextResumeFailureCriticalityDiagnosticsIEBinding {
		sealed := s27.UEContextResumeFailureCriticalityDiagnosticsIEBinding{}
		*s27.BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldInfo(&sealed) = t.infoCriticalityDiagnostics()
		*s27.BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldCodec(&sealed) = func() s26.CriticalityDiagnosticsValueCodec {
			sealed := s26.CriticalityDiagnosticsValueCodec{}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
				var zero s27.UEContextResumeFailureIEValue
				decoded, err := s27.BridgeUEContextResumeFailureIEValueMethodDecode(zero, s00.ProtocolIEID(58), raw)
				if err != nil {
					var empty s26.CriticalityDiagnostics
					return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
				}
				value, ok := decoded.AsCriticalityDiagnostics()
				if !ok {
					var empty s26.CriticalityDiagnostics
					return empty, fmt.Errorf("binding UEContextResumeFailureIEs.id-CriticalityDiagnostics: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s27.BridgeUEContextResumeFailureIEValueMethodEncodeFresh((func() s27.UEContextResumeFailureIEValue {
					sealed := s27.UEContextResumeFailureIEValue{}
					*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
					*s27.BridgeUEContextResumeFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s27.BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldInject(&sealed) = func(value s26.CriticalityDiagnostics) s27.UEContextResumeFailureIEValue {
			return func() s27.UEContextResumeFailureIEValue {
				sealed := s27.UEContextResumeFailureIEValue{}
				*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = s00.ProtocolIEID(58)
				*s27.BridgeUEContextResumeFailureIEValueFieldRowCriticalityDiagnostics(&sealed) = &value
				return sealed
			}()
		}
		*s27.BridgeUEContextResumeFailureCriticalityDiagnosticsIEBindingFieldGet(&sealed) = func(value *s27.UEContextResumeFailureIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextResumeFailureIETable.
func (t UEContextResumeFailureIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s27.UEContextResumeFailureIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return s27.UEContextResumeFailureIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s27.UEContextResumeFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s27.UEContextResumeFailureIEField{}, aper.OperationError(err, "Opaque")
		}
		return s27.UEContextResumeFailureIEField{Id: id, Criticality: criticality, Value: func() s27.UEContextResumeFailureIEValue {
			sealed := s27.UEContextResumeFailureIEValue{}
			*s27.BridgeUEContextResumeFailureIEValueFieldId(&sealed) = id
			*s27.BridgeUEContextResumeFailureIEValueFieldOpaque(&sealed) = opaque
			*s27.BridgeUEContextResumeFailureIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type UERadioCapabilityIDMappingResponseIETable struct{}

func UERadioCapabilityIDMappingResponseIEs() UERadioCapabilityIDMappingResponseIETable {
	return UERadioCapabilityIDMappingResponseIETable{}
}

// ID returns the ASN.1 object-set identity of UERadioCapabilityIDMappingResponseIETable.
func (UERadioCapabilityIDMappingResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UERadioCapabilityIDMappingResponseIETable.
func (UERadioCapabilityIDMappingResponseIETable) Table() s00.UERadioCapabilityIDMappingResponseIEValueIETable {
	return func() s00.UERadioCapabilityIDMappingResponseIEValueIETable {
		sealed := s00.UERadioCapabilityIDMappingResponseIEValueIETable{}
		*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UERadioCapabilityIDMappingResponseIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of UERadioCapabilityIDMappingResponseIETable.
func (t UERadioCapabilityIDMappingResponseIETable) UERadioCapabilityID() UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding {
	return UERadioCapabilityIDMappingResponseUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero UERadioCapabilityIDMappingResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapabilityID, options aper.DecodeState) (s00.UERadioCapabilityID, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapabilityID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapabilityID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APUERadioCapabilityID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapabilityID) UERadioCapabilityIDMappingResponseIEValue {
			return UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (UERadioCapabilityIDMappingResponseIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of UERadioCapabilityIDMappingResponseIETable.
func (t UERadioCapabilityIDMappingResponseIETable) UERadioCapability() UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding {
	return UERadioCapabilityIDMappingResponseUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapability")
			var zero UERadioCapabilityIDMappingResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, runtime.WrapDecodePath(err, "UERadioCapability")
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapability, options aper.DecodeState) (s00.UERadioCapability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APUERadioCapability(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapability) UERadioCapabilityIDMappingResponseIEValue {
			return UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *UERadioCapabilityIDMappingResponseIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (UERadioCapabilityIDMappingResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityIDMappingResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityIDMappingResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UERadioCapabilityIDMappingResponseIETable.
func (t UERadioCapabilityIDMappingResponseIETable) CriticalityDiagnostics() UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding {
	return UERadioCapabilityIDMappingResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero UERadioCapabilityIDMappingResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UERadioCapabilityIDMappingResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) UERadioCapabilityIDMappingResponseIEValue {
			return UERadioCapabilityIDMappingResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UERadioCapabilityIDMappingResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UERadioCapabilityIDMappingResponseIETable.
func (t UERadioCapabilityIDMappingResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UERadioCapabilityIDMappingResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(314):
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UERadioCapabilityIDMappingResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UERadioCapabilityIDMappingResponseIEField{Id: id, Criticality: criticality, Value: UERadioCapabilityIDMappingResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UERadioCapabilityMatchResponseIETable struct{}

func UERadioCapabilityMatchResponseIEs() UERadioCapabilityMatchResponseIETable {
	return UERadioCapabilityMatchResponseIETable{}
}

// ID returns the ASN.1 object-set identity of UERadioCapabilityMatchResponseIETable.
func (UERadioCapabilityMatchResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UERadioCapabilityMatchResponseIETable.
func (UERadioCapabilityMatchResponseIETable) Table() s00.UERadioCapabilityMatchResponseIEValueIETable {
	return func() s00.UERadioCapabilityMatchResponseIEValueIETable {
		sealed := s00.UERadioCapabilityMatchResponseIEValueIETable{}
		*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UERadioCapabilityMatchResponseIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UERadioCapabilityMatchResponseIETable.
func (t UERadioCapabilityMatchResponseIETable) MMEUES1APID() UERadioCapabilityMatchResponseMMEUES1APIDIEBinding {
	return UERadioCapabilityMatchResponseMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UERadioCapabilityMatchResponseIETable.
func (t UERadioCapabilityMatchResponseIETable) ENBUES1APID() UERadioCapabilityMatchResponseENBUES1APIDIEBinding {
	return UERadioCapabilityMatchResponseENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoVoiceSupportMatchIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(169), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "VoiceSupportMatchIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-VoiceSupportMatchIndicator"}}}
}

// VoiceSupportMatchIndicator returns the typed binding for the VoiceSupportMatchIndicator row of UERadioCapabilityMatchResponseIETable.
func (t UERadioCapabilityMatchResponseIETable) VoiceSupportMatchIndicator() UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding {
	return UERadioCapabilityMatchResponseVoiceSupportMatchIndicatorIEBinding{info: t.infoVoiceSupportMatchIndicator(), codec: func() s02.VoiceSupportMatchIndicatorValueCodec {
		sealed := s02.VoiceSupportMatchIndicatorValueCodec{}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldPath(&sealed) = "VoiceSupportMatchIndicator"
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.VoiceSupportMatchIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.VoiceSupportMatchIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("VoiceSupportMatchIndicator")
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(169), raw)
			if err != nil {
				var empty s00.VoiceSupportMatchIndicator
				return empty, runtime.WrapDecodePath(err, "VoiceSupportMatchIndicator")
			}
			value, ok := decoded.AsVoiceSupportMatchIndicator()
			if !ok {
				var empty s00.VoiceSupportMatchIndicator
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-VoiceSupportMatchIndicator: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldEncode(&sealed) = func(value s00.VoiceSupportMatchIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(169), rowVoiceSupportMatchIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldCapture(&sealed) = func(v s00.VoiceSupportMatchIndicator, options aper.DecodeState) (s00.VoiceSupportMatchIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APVoiceSupportMatchIndicator(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldCompare(&sealed) = func(v s00.VoiceSupportMatchIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APVoiceSupportMatchIndicator(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeVoiceSupportMatchIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:VoiceSupportMatchIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.VoiceSupportMatchIndicator) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(169), rowVoiceSupportMatchIndicator: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s00.VoiceSupportMatchIndicator, bool) {
			return value.AsVoiceSupportMatchIndicator()
		}}
}
func (UERadioCapabilityMatchResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: UERadioCapabilityMatchResponseIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UERadioCapabilityMatchResponseIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of UERadioCapabilityMatchResponseIETable.
func (t UERadioCapabilityMatchResponseIETable) CriticalityDiagnostics() UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding {
	return UERadioCapabilityMatchResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero UERadioCapabilityMatchResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding UERadioCapabilityMatchResponseIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) UERadioCapabilityMatchResponseIEValue {
			return UERadioCapabilityMatchResponseIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *UERadioCapabilityMatchResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UERadioCapabilityMatchResponseIETable.
func (t UERadioCapabilityMatchResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UERadioCapabilityMatchResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(169):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-VoiceSupportMatchIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UERadioCapabilityMatchResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return UERadioCapabilityMatchResponseIEField{Id: id, Criticality: criticality, Value: UERadioCapabilityMatchResponseIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CellStateIndicationCodec binds the complete source value type.
func CellStateIndicationCodec() CellStateIndicationValueCodec {
	return CellStateIndicationValueCodec{path: "CellStateIndication", decode: func(data []byte, options aper.DecodeState) (CellStateIndication, error) {
		var value CellStateIndication
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellStateIndication{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellStateIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellStateIndication, options aper.DecodeState) (CellStateIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellStateIndication(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellStateIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellStateIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellStateIndication"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// InterSystemMeasurementParametersCodec binds the complete source value type.
func InterSystemMeasurementParametersCodec() InterSystemMeasurementParametersValueCodec {
	return InterSystemMeasurementParametersValueCodec{path: "InterSystemMeasurementParameters", decode: func(data []byte, options aper.DecodeState) (InterSystemMeasurementParameters, error) {
		var value InterSystemMeasurementParameters
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InterSystemMeasurementParameters{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InterSystemMeasurementParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InterSystemMeasurementParameters, options aper.DecodeState) (InterSystemMeasurementParameters, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APInterSystemMeasurementParameters(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v InterSystemMeasurementParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APInterSystemMeasurementParameters(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemMeasurementParameters"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LoggedMBSFNMDTCodec binds the complete APER value type.
func LoggedMBSFNMDTCodec() LoggedMBSFNMDTValueCodec {
	return MDTModeExtensionIE().LoggedMBSFNMDT().Codec()
}

// MultiCellLoadReportingRequestCodec binds the complete source value type.
func MultiCellLoadReportingRequestCodec() MultiCellLoadReportingRequestValueCodec {
	return MultiCellLoadReportingRequestValueCodec{path: "MultiCellLoadReportingRequest", decode: func(data []byte, options aper.DecodeState) (MultiCellLoadReportingRequest, error) {
		var value MultiCellLoadReportingRequest
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MultiCellLoadReportingRequest{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MultiCellLoadReportingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MultiCellLoadReportingRequest, options aper.DecodeState) (MultiCellLoadReportingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APMultiCellLoadReportingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MultiCellLoadReportingRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeCompareS1APMultiCellLoadReportingRequest(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MultiCellLoadReportingRequest"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONtransferRequestContainerCodec binds the complete source value type.
func SONtransferRequestContainerCodec() SONtransferRequestContainerValueCodec {
	return SONtransferRequestContainerValueCodec{path: "SONtransferRequestContainer", decode: func(data []byte, options aper.DecodeState) (SONtransferRequestContainer, error) {
		var value SONtransferRequestContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferRequestContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferRequestContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferRequestContainer, options aper.DecodeState) (SONtransferRequestContainer, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferRequestContainer(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferRequestContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APSONtransferRequestContainer(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferRequestContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONtransferResponseContainerCodec binds the complete source value type.
func SONtransferResponseContainerCodec() SONtransferResponseContainerValueCodec {
	return SONtransferResponseContainerValueCodec{path: "SONtransferResponseContainer", decode: func(data []byte, options aper.DecodeState) (SONtransferResponseContainer, error) {
		var value SONtransferResponseContainer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONtransferResponseContainer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONtransferResponseContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONtransferResponseContainer, options aper.DecodeState) (SONtransferResponseContainer, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONtransferResponseContainer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONtransferResponseContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APSONtransferResponseContainer(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONtransferResponseContainer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// VoiceSupportMatchIndicatorCodec binds the complete APER value type.
func VoiceSupportMatchIndicatorCodec() s02.VoiceSupportMatchIndicatorValueCodec {
	return UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Codec()
}
func BridgeENBConfigurationUpdateAcknowledgeFieldPerPadding(v *ENBConfigurationUpdateAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceived(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.received
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedAbsolute(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedBytes(v *ENBConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationUpdateAcknowledgeFieldReceivedLocation(v *ENBConfigurationUpdateAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v *ENBConfigurationUpdateAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdateAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCapture(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCompare(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldContext(v *ENBConfigurationUpdateAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldDecode(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldEncode(v *ENBConfigurationUpdateAcknowledgeValueCodec) *func(ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldPath(v *ENBConfigurationUpdateAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationUpdateFailureFieldPerPadding(v *ENBConfigurationUpdateFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBConfigurationUpdateFailureFieldReceived(v *ENBConfigurationUpdateFailure) *bool {
	return &v.received
}
func BridgeENBConfigurationUpdateFailureFieldReceivedAbsolute(v *ENBConfigurationUpdateFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeENBConfigurationUpdateFailureFieldReceivedBytes(v *ENBConfigurationUpdateFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBConfigurationUpdateFailureFieldReceivedLocation(v *ENBConfigurationUpdateFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v *ENBConfigurationUpdateFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERFrom(v *ENBConfigurationUpdateFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERWithOptions(v *ENBConfigurationUpdateFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldCapture(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, aper.DecodeState) (ENBConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldCompare(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldContext(v *ENBConfigurationUpdateFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldDecode(v *ENBConfigurationUpdateFailureValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldEncode(v *ENBConfigurationUpdateFailureValueCodec) *func(ENBConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureValueCodecFieldPath(v *ENBConfigurationUpdateFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferFieldPerPadding(v *ENBStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBStatusTransferFieldReceived(v *ENBStatusTransfer) *bool { return &v.received }
func BridgeENBStatusTransferFieldReceivedAbsolute(v *ENBStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBStatusTransferFieldReceivedBytes(v *ENBStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBStatusTransferFieldReceivedLocation(v *ENBStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBStatusTransferMethodMarshalAPERBudget(v *ENBStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBStatusTransferMethodUnmarshalAPERFrom(v *ENBStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferMethodUnmarshalAPERWithOptions(v *ENBStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBStatusTransferValueCodecFieldCapture(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, aper.DecodeState) (ENBStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferValueCodecFieldCompare(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferValueCodecFieldContext(v *ENBStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferValueCodecFieldDecode(v *ENBStatusTransferValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransfer, error) {
	return &v.decode
}
func BridgeENBStatusTransferValueCodecFieldEncode(v *ENBStatusTransferValueCodec) *func(ENBStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferValueCodecFieldPath(v *ENBStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntersystemMeasurementConfigurationFieldPerPadding(v *IntersystemMeasurementConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeIntersystemMeasurementConfigurationFieldReceived(v *IntersystemMeasurementConfiguration) *bool {
	return &v.received
}
func BridgeIntersystemMeasurementConfigurationFieldReceivedBytes(v *IntersystemMeasurementConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeIntersystemMeasurementConfigurationFieldReceivedLocation(v *IntersystemMeasurementConfiguration) *aper.Location {
	return &v.receivedLocation
}
func BridgeIntersystemMeasurementConfigurationMethodMarshalAPERBudget(v *IntersystemMeasurementConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERFrom(v *IntersystemMeasurementConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldCapture(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, aper.DecodeState) (IntersystemMeasurementConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldCompare(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldContext(v *IntersystemMeasurementConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldDecode(v *IntersystemMeasurementConfigurationValueCodec) *func([]byte, aper.DecodeState) (IntersystemMeasurementConfiguration, error) {
	return &v.decode
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldEncode(v *IntersystemMeasurementConfigurationValueCodec) *func(IntersystemMeasurementConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntersystemMeasurementConfigurationValueCodecFieldPath(v *IntersystemMeasurementConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldCapture(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, aper.DecodeState) (MDTModeExtensionIEIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldCompare(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldContext(v *MDTModeExtensionIEIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldDecode(v *MDTModeExtensionIEIEContainerValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEContainer, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldEncode(v *MDTModeExtensionIEIEContainerValueCodec) *func(MDTModeExtensionIEIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEContainerValueCodecFieldPath(v *MDTModeExtensionIEIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEFieldFieldReplay(v *MDTModeExtensionIEIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMDTModeExtensionIEIEFieldFieldWithoutReplay(v *MDTModeExtensionIEIEField) *bool {
	return &v.withoutReplay
}
func BridgeMDTModeExtensionIEIEFieldMethodMarshalAPERTo(v *MDTModeExtensionIEIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMDTModeExtensionIEIEFieldMethodUnmarshalAPERFrom(v *MDTModeExtensionIEIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldCapture(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, aper.DecodeState) (MDTModeExtensionIEIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldCompare(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldContext(v *MDTModeExtensionIEIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldDecode(v *MDTModeExtensionIEIEFieldValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEField, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldEncode(v *MDTModeExtensionIEIEFieldValueCodec) *func(MDTModeExtensionIEIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEFieldValueCodecFieldPath(v *MDTModeExtensionIEIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueERABIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueFieldId(v *MDTModeExtensionIEIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMDTModeExtensionIEIEValueFieldIsOpaque(v *MDTModeExtensionIEIEValue) *bool {
	return &v.isOpaque
}
func BridgeMDTModeExtensionIEIEValueFieldOpaque(v *MDTModeExtensionIEIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMDTModeExtensionIEIEValueFieldRowLoggedMBSFNMDT(v *MDTModeExtensionIEIEValue) **LoggedMBSFNMDT {
	return &v.rowLoggedMBSFNMDT
}
func BridgeMDTModeExtensionIEIEValueMethodCaptureSemantics(v MDTModeExtensionIEIEValue, a0 aper.SemanticCapture) MDTModeExtensionIEIEValue {
	return v.captureSemantics(a0)
}
func BridgeMDTModeExtensionIEIEValueMethodCompareSemantics(v MDTModeExtensionIEIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCapture(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldCompare(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldContext(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldDecode(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MDTModeExtensionIEIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldEncode(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *func(MDTModeExtensionIEIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTModeExtensionIEIEValueProtocolIEContainerListValueCodecFieldPath(v *MDTModeExtensionIEIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePC5QoSParametersFieldPerPadding(v *PC5QoSParameters) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePC5QoSParametersFieldReceived(v *PC5QoSParameters) *bool { return &v.received }
func BridgePC5QoSParametersFieldReceivedBytes(v *PC5QoSParameters) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePC5QoSParametersFieldReceivedLocation(v *PC5QoSParameters) *aper.Location {
	return &v.receivedLocation
}
func BridgePC5QoSParametersMethodMarshalAPERBudget(v *PC5QoSParameters, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePC5QoSParametersMethodUnmarshalAPERFrom(v *PC5QoSParameters, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePC5QoSParametersValueCodecFieldCapture(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, aper.DecodeState) (PC5QoSParameters, aper.Snapshot) {
	return &v.capture
}
func BridgePC5QoSParametersValueCodecFieldCompare(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePC5QoSParametersValueCodecFieldContext(v *PC5QoSParametersValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePC5QoSParametersValueCodecFieldDecode(v *PC5QoSParametersValueCodec) *func([]byte, aper.DecodeState) (PC5QoSParameters, error) {
	return &v.decode
}
func BridgePC5QoSParametersValueCodecFieldEncode(v *PC5QoSParametersValueCodec) *func(PC5QoSParameters, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePC5QoSParametersValueCodecFieldPath(v *PC5QoSParametersValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONtransferRequestContainerMethodMarshalAPERBudget(v *SONtransferRequestContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONtransferResponseContainerMethodMarshalAPERBudget(v *SONtransferResponseContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *func(s27.UEContextResumeFailureIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextResumeFailureIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEContainer, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *func(UERadioCapabilityIDMappingResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v *UERadioCapabilityIDMappingResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(v *UERadioCapabilityIDMappingResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEField, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *func(UERadioCapabilityIDMappingResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldId(v *UERadioCapabilityIDMappingResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldIsOpaque(v *UERadioCapabilityIDMappingResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldOpaque(v *UERadioCapabilityIDMappingResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowCriticalityDiagnostics(v *UERadioCapabilityIDMappingResponseIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapability(v *UERadioCapabilityIDMappingResponseIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeUERadioCapabilityIDMappingResponseIEValueFieldRowUERadioCapabilityID(v *UERadioCapabilityIDMappingResponseIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodCaptureSemantics(v UERadioCapabilityIDMappingResponseIEValue, a0 aper.SemanticCapture) UERadioCapabilityIDMappingResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodCompareSemantics(v UERadioCapabilityIDMappingResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodMatchesID(v UERadioCapabilityIDMappingResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(v UERadioCapabilityIDMappingResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEContainer, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *func(UERadioCapabilityMatchResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v *UERadioCapabilityMatchResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v *UERadioCapabilityMatchResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(v *UERadioCapabilityMatchResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEField, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *func(UERadioCapabilityMatchResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldId(v *UERadioCapabilityMatchResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldIsOpaque(v *UERadioCapabilityMatchResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldOpaque(v *UERadioCapabilityMatchResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowCriticalityDiagnostics(v *UERadioCapabilityMatchResponseIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowENBUES1APID(v *UERadioCapabilityMatchResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowMMEUES1APID(v *UERadioCapabilityMatchResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUERadioCapabilityMatchResponseIEValueFieldRowVoiceSupportMatchIndicator(v *UERadioCapabilityMatchResponseIEValue) **s00.VoiceSupportMatchIndicator {
	return &v.rowVoiceSupportMatchIndicator
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodCaptureSemantics(v UERadioCapabilityMatchResponseIEValue, a0 aper.SemanticCapture) UERadioCapabilityMatchResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodCompareSemantics(v UERadioCapabilityMatchResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(v UERadioCapabilityMatchResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseIEValueMethodRule(v UERadioCapabilityMatchResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *func(UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MDTModeExtensionIEIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 197:
		if value, ok := v.AsLoggedMBSFNMDT(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UERadioCapabilityIDMappingResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 314:
		if value, ok := v.AsUERadioCapabilityID(); ok {
			return value, true
		}
	case 74:
		if value, ok := v.AsUERadioCapability(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UERadioCapabilityMatchResponseIEValue) Selected() (any, bool) {
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
	case 169:
		if value, ok := v.AsVoiceSupportMatchIndicator(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
