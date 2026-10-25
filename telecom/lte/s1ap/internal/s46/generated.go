// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s46 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s46

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// PathSwitchRequestAcknowledgeIEContainer is the concrete ProtocolIEContainer[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEContainer []PathSwitchRequestAcknowledgeIEField

// PathSwitchRequestAcknowledgeIEField is the concrete ProtocolIEField[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PathSwitchRequestAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEField) WithoutReplay() PathSwitchRequestAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PathSwitchRequestAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PathSwitchRequestAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *PathSwitchRequestAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestAcknowledgeIEField{}
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
	var zero PathSwitchRequestAcknowledgeIEValue

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

// UEContextModificationRequestIEContainer is the concrete ProtocolIEContainer[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEContainer []UEContextModificationRequestIEField

// UEContextModificationRequestIEField is the concrete ProtocolIEField[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEField) WithoutReplay() UEContextModificationRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextModificationRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationRequestIEField{}
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
	var zero UEContextModificationRequestIEValue

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
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(v *s45.ERABSetupResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(v *s45.ERABSetupResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *PathSwitchRequestAcknowledgeIEContainer, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(v *s45.SecondaryRATDataUsageReportIEContainer, s *aper.SemanticCapture) {
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
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(v *s45.SecondaryRATDataUsageReportIEContainer, s *aper.SemanticComparison) {
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
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(v *s45.UEContextReleaseCompleteIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(v *s45.UEContextReleaseCompleteIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(v *s45.UEContextSuspendRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(v *s45.UEContextSuspendRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.V2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.V2XServicesAuthorizedExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// V2XServicesAuthorizedValueCodec is the concrete ValueCodec[V2XServicesAuthorized].
type V2XServicesAuthorizedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (V2XServicesAuthorized,

		error)
	encode func(V2XServicesAuthorized,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(V2XServicesAuthorized, aper.DecodeState,

	) (V2XServicesAuthorized, aper.Snapshot,

	)
	compare func(V2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c V2XServicesAuthorizedValueCodec) New(value V2XServicesAuthorized,

) (V2XServicesAuthorizedAPERValue, error) {
	if c.encode == nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return V2XServicesAuthorizedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c V2XServicesAuthorizedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (V2XServicesAuthorizedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return V2XServicesAuthorizedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return V2XServicesAuthorizedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return V2XServicesAuthorizedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return V2XServicesAuthorizedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c V2XServicesAuthorizedValueCodec) EncodeAPER(value V2XServicesAuthorizedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c V2XServicesAuthorizedValueCodec) encodeBudgetValue(value V2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c V2XServicesAuthorizedValueCodec) encodeChanged(value V2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding is the concrete IEBinding[UEAggregateMaximumBitrate, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding is the concrete IEBinding[ERABToBeSwitchedULList, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding struct {
	info   s00.FieldInfo
	codec  s17.ERABToBeSwitchedULListValueCodec
	inject func(s17.ERABToBeSwitchedULList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s17.ERABToBeSwitchedULList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Codec() s17.ERABToBeSwitchedULListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) New(value s17.ERABToBeSwitchedULList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeERABToBeSwitchedULListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s17.ERABToBeSwitchedULList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABListIEBinding is the concrete IEBinding[ERABList, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABListValueCodec
	inject func(s16.ERABList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s16.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Codec() s16.ERABListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) New(value s16.ERABList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s16.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeSecurityContextIEBinding is the concrete IEBinding[SecurityContext, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeSecurityContextIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecurityContextValueCodec
	inject func(s28.SecurityContext,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s28.SecurityContext,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Codec() s28.SecurityContextValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) New(value s28.SecurityContext,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecurityContextValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s28.SecurityContext,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding is the concrete IEBinding[CSGMembershipStatus, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding is the concrete IEBinding[ProSeAuthorized, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ProSeAuthorizedValueCodec
	inject func(s20.ProSeAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s20.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Codec() s20.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) New(value s20.ProSeAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s20.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding is the concrete IEBinding[UEUserPlaneCIoTSupportIndicator, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUserPlaneCIoTSupportIndicatorValueCodec
	inject func(s00.UEUserPlaneCIoTSupportIndicator,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.UEUserPlaneCIoTSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Codec() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) New(value s00.UEUserPlaneCIoTSupportIndicator,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.UEUserPlaneCIoTSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding is the concrete IEBinding[V2XServicesAuthorized, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  V2XServicesAuthorizedValueCodec
	inject func(V2XServicesAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Codec() V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) New(value V2XServicesAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[UESidelinkAggregateMaximumBitrate, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s37.UESidelinkAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s37.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Codec() s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) New(value s37.UESidelinkAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s37.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding is the concrete IEBinding[EnhancedCoverageRestricted, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding is the concrete IEBinding[NRUESecurityCapabilities, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding is the concrete IEBinding[CEModeBRestricted, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding is the concrete IEBinding[AerialUEsubscriptionInformation, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgePendingDataIndicationIEBinding is the concrete IEBinding[PendingDataIndication, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgePendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding is the concrete IEBinding[SubscriptionBasedUEDifferentiationInfo, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s30.SubscriptionBasedUEDifferentiationInfo,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s30.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s30.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding is the concrete IEBinding[HandoverRestrictionList, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding struct {
	info   s00.FieldInfo
	codec  s42.HandoverRestrictionListValueCodec
	inject func(s42.HandoverRestrictionList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s42.HandoverRestrictionList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Codec() s42.HandoverRestrictionListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) New(value s42.HandoverRestrictionList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s42.BridgeHandoverRestrictionListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s42.HandoverRestrictionList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding is the concrete IEBinding[AdditionalRRMPriorityIndex, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding is the concrete IEBinding[NRV2XServicesAuthorized, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRV2XServicesAuthorizedValueCodec
	inject func(s19.NRV2XServicesAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s19.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Codec() s19.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) New(value s19.NRV2XServicesAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s19.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[NRUESidelinkAggregateMaximumBitrate, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s19.NRUESidelinkAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s19.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s19.NRUESidelinkAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s19.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgePC5QoSParametersIEBinding is the concrete IEBinding[PC5QoSParameters, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgePC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s24.PC5QoSParametersValueCodec
	inject func(s24.PC5QoSParameters,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s24.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Codec() s24.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) New(value s24.PC5QoSParameters,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s24.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s24.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding is the concrete IEBinding[UESecurityCapabilities, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding is the concrete IEBinding[ERABToBeUpdatedList, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding struct {
	info   s00.FieldInfo
	codec  s29.ERABToBeUpdatedListValueCodec
	inject func(s29.ERABToBeUpdatedList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s29.ERABToBeUpdatedList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Codec() s29.ERABToBeUpdatedListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) New(value s29.ERABToBeUpdatedList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s29.BridgeERABToBeUpdatedListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s29.ERABToBeUpdatedList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding is the concrete IEBinding[TimeRefDistribution, PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.TimeRefDistribution,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextModificationRequestIEValue].
type UEContextModificationRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextModificationRequestIEValue].
type UEContextModificationRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSecurityKeyIEBinding is the concrete IEBinding[SecurityKey, UEContextModificationRequestIEValue].
type UEContextModificationRequestSecurityKeyIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SecurityKeyValueCodec
	inject func(s00.SecurityKey,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SecurityKey,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Codec() s01.SecurityKeyValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSecurityKeyIEBinding) New(value s00.SecurityKey,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSecurityKeyValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SecurityKey,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSubscriberProfileIDforRFPIEBinding is the concrete IEBinding[SubscriberProfileIDforRFP, UEContextModificationRequestIEValue].
type UEContextModificationRequestSubscriberProfileIDforRFPIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SubscriberProfileIDforRFPValueCodec
	inject func(s00.SubscriberProfileIDforRFP,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SubscriberProfileIDforRFP,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Codec() s01.SubscriberProfileIDforRFPValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) New(value s00.SubscriberProfileIDforRFP,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SubscriberProfileIDforRFP,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUEAggregateMaximumBitrateIEBinding is the concrete IEBinding[UEAggregateMaximumBitrate, UEContextModificationRequestIEValue].
type UEContextModificationRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s35.UEAggregateMaximumBitrateValueCodec
	inject func(s35.UEAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s35.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Codec() s35.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) New(value s35.UEAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s35.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestCSFallbackIndicatorIEBinding is the concrete IEBinding[CSFallbackIndicator, UEContextModificationRequestIEValue].
type UEContextModificationRequestCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSFallbackIndicatorValueCodec
	inject func(s00.CSFallbackIndicator,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.CSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Codec() s00.CSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) New(value s00.CSFallbackIndicator,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.CSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUESecurityCapabilitiesIEBinding is the concrete IEBinding[UESecurityCapabilities, UEContextModificationRequestIEValue].
type UEContextModificationRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Get(field *UEContextModificationRequestIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestCSGMembershipStatusIEBinding is the concrete IEBinding[CSGMembershipStatus, UEContextModificationRequestIEValue].
type UEContextModificationRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestLAIIEBinding is the concrete IEBinding[LAI, UEContextModificationRequestIEValue].
type UEContextModificationRequestLAIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LAIValueCodec
	inject func(s18.LAI,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s18.LAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestLAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestLAIIEBinding) Codec() s18.LAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestLAIIEBinding) New(value s18.LAI,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestLAIIEBinding) Get(field *UEContextModificationRequestIEField) (*s18.LAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding is the concrete IEBinding[AdditionalCSFallbackIndicator, UEContextModificationRequestIEValue].
type UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalCSFallbackIndicatorValueCodec
	inject func(s00.AdditionalCSFallbackIndicator,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AdditionalCSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Codec() s00.AdditionalCSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) New(value s00.AdditionalCSFallbackIndicator,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AdditionalCSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestProSeAuthorizedIEBinding is the concrete IEBinding[ProSeAuthorized, UEContextModificationRequestIEValue].
type UEContextModificationRequestProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ProSeAuthorizedValueCodec
	inject func(s20.ProSeAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s20.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Codec() s20.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) New(value s20.ProSeAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s20.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSRVCCOperationPossibleIEBinding is the concrete IEBinding[SRVCCOperationPossible, UEContextModificationRequestIEValue].
type UEContextModificationRequestSRVCCOperationPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCOperationPossibleValueCodec
	inject func(s00.SRVCCOperationPossible,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SRVCCOperationPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Codec() s01.SRVCCOperationPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) New(value s00.SRVCCOperationPossible,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SRVCCOperationPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSRVCCOperationNotPossibleIEBinding is the concrete IEBinding[SRVCCOperationNotPossible, UEContextModificationRequestIEValue].
type UEContextModificationRequestSRVCCOperationNotPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCOperationNotPossibleValueCodec
	inject func(s00.SRVCCOperationNotPossible,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SRVCCOperationNotPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Codec() s01.SRVCCOperationNotPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) New(value s00.SRVCCOperationNotPossible,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SRVCCOperationNotPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestV2XServicesAuthorizedIEBinding is the concrete IEBinding[V2XServicesAuthorized, UEContextModificationRequestIEValue].
type UEContextModificationRequestV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  V2XServicesAuthorizedValueCodec
	inject func(V2XServicesAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Codec() V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) New(value V2XServicesAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[UESidelinkAggregateMaximumBitrate, UEContextModificationRequestIEValue].
type UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s37.UESidelinkAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s37.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Codec() s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) New(value s37.UESidelinkAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s37.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRUESecurityCapabilitiesIEBinding is the concrete IEBinding[NRUESecurityCapabilities, UEContextModificationRequestIEValue].
type UEContextModificationRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Get(field *UEContextModificationRequestIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAerialUEsubscriptionInformationIEBinding is the concrete IEBinding[AerialUEsubscriptionInformation, UEContextModificationRequestIEValue].
type UEContextModificationRequestAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding is the concrete IEBinding[AdditionalRRMPriorityIndex, UEContextModificationRequestIEValue].
type UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestIABAuthorizedIEBinding is the concrete IEBinding[IABAuthorized, UEContextModificationRequestIEValue].
type UEContextModificationRequestIABAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.IABAuthorizedValueCodec
	inject func(s00.IABAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.IABAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Codec() s00.IABAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestIABAuthorizedIEBinding) New(value s00.IABAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeIABAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.IABAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRV2XServicesAuthorizedIEBinding is the concrete IEBinding[NRV2XServicesAuthorized, UEContextModificationRequestIEValue].
type UEContextModificationRequestNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRV2XServicesAuthorizedValueCodec
	inject func(s19.NRV2XServicesAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s19.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Codec() s19.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) New(value s19.NRV2XServicesAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s19.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding is the concrete IEBinding[NRUESidelinkAggregateMaximumBitrate, UEContextModificationRequestIEValue].
type UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s19.NRUESidelinkAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s19.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s19.NRUESidelinkAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s19.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestPC5QoSParametersIEBinding is the concrete IEBinding[PC5QoSParameters, UEContextModificationRequestIEValue].
type UEContextModificationRequestPC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s24.PC5QoSParametersValueCodec
	inject func(s24.PC5QoSParameters,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s24.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Codec() s24.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) New(value s24.PC5QoSParameters,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s24.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Get(field *UEContextModificationRequestIEField) (*s24.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, UEContextModificationRequestIEValue].
type UEContextModificationRequestUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestTimeRefDistributionIEBinding is the concrete IEBinding[TimeRefDistribution, UEContextModificationRequestIEValue].
type UEContextModificationRequestTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.TimeRefDistribution,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABReleaseResponseValueCodec is the concrete ValueCodec[ERABReleaseResponse].
type ERABReleaseResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABReleaseResponse,

		error)
	encode func(ERABReleaseResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABReleaseResponse, aper.DecodeState,

	) (ERABReleaseResponse, aper.Snapshot,

	)
	compare func(ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABReleaseResponseValueCodec) New(value ERABReleaseResponse,

) (ERABReleaseResponseAPERValue, error) {
	if c.encode == nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABReleaseResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABReleaseResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABReleaseResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABReleaseResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABReleaseResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABReleaseResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABReleaseResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABReleaseResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABReleaseResponseValueCodec) EncodeAPER(value ERABReleaseResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABReleaseResponseValueCodec) encodeBudgetValue(value ERABReleaseResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABReleaseResponseValueCodec) encodeChanged(value ERABReleaseResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABSetupResponseValueCodec is the concrete ValueCodec[ERABSetupResponse].
type ERABSetupResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABSetupResponse,

		error)
	encode func(ERABSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABSetupResponse, aper.DecodeState,

	) (ERABSetupResponse, aper.Snapshot,

	)
	compare func(ERABSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABSetupResponseValueCodec) New(value ERABSetupResponse,

) (ERABSetupResponseAPERValue, error) {
	if c.encode == nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABSetupResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABSetupResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABSetupResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABSetupResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABSetupResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABSetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABSetupResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABSetupResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABSetupResponseValueCodec) EncodeAPER(value ERABSetupResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ERABSetupResponseValueCodec) encodeBudgetValue(value ERABSetupResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABSetupResponseValueCodec) encodeChanged(value ERABSetupResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageReportValueCodec is the concrete ValueCodec[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SecondaryRATDataUsageReport,

		error)
	encode func(SecondaryRATDataUsageReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SecondaryRATDataUsageReport, aper.DecodeState,

	) (SecondaryRATDataUsageReport, aper.Snapshot,

	)
	compare func(SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageReportValueCodec) New(value SecondaryRATDataUsageReport,

) (SecondaryRATDataUsageReportAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageReportValueCodec) EncodeAPER(value SecondaryRATDataUsageReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SecondaryRATDataUsageReportValueCodec) encodeBudgetValue(value SecondaryRATDataUsageReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageReportValueCodec) encodeChanged(value SecondaryRATDataUsageReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCompleteValueCodec is the concrete ValueCodec[UEContextReleaseComplete].
type UEContextReleaseCompleteValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseComplete,

		error)
	encode func(UEContextReleaseComplete,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseComplete, aper.DecodeState,

	) (UEContextReleaseComplete, aper.Snapshot,

	)
	compare func(UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCompleteValueCodec) New(value UEContextReleaseComplete,

) (UEContextReleaseCompleteAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCompleteAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCompleteAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCompleteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCompleteAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCompleteAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCompleteAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCompleteAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCompleteAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCompleteValueCodec) EncodeAPER(value UEContextReleaseCompleteAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextReleaseCompleteValueCodec) encodeBudgetValue(value UEContextReleaseComplete,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCompleteValueCodec) encodeChanged(value UEContextReleaseComplete,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendRequestValueCodec is the concrete ValueCodec[UEContextSuspendRequest].
type UEContextSuspendRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendRequest,

		error)
	encode func(UEContextSuspendRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendRequest, aper.DecodeState,

	) (UEContextSuspendRequest, aper.Snapshot,

	)
	compare func(UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendRequestValueCodec) New(value UEContextSuspendRequest,

) (UEContextSuspendRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendRequestValueCodec) EncodeAPER(value UEContextSuspendRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextSuspendRequestValueCodec) encodeBudgetValue(value UEContextSuspendRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendRequestValueCodec) encodeChanged(value UEContextSuspendRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABSetupResponseIEValueValidateS1APIEContainer(fields s45.ERABSetupResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s45.BridgeERABSetupResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s45.BridgeERABSetupResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s45.BridgeERABSetupResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeERABReleaseResponseIEValueValidateS1APIEContainer(fields s45.ERABReleaseResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s45.BridgeERABReleaseResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s45.BridgeERABReleaseResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s45.BridgeERABReleaseResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(fields s45.UEContextReleaseCompleteIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s45.BridgeUEContextReleaseCompleteIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s45.BridgeUEContextReleaseCompleteIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s45.BridgeUEContextReleaseCompleteIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(fields s45.UEContextSuspendRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s45.BridgeUEContextSuspendRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s45.BridgeUEContextSuspendRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s45.BridgeUEContextSuspendRequestIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(fields s45.SecondaryRATDataUsageReportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s45.BridgeSecondaryRATDataUsageReportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s45.BridgeSecondaryRATDataUsageReportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s45.BridgeSecondaryRATDataUsageReportIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeUserLocationInformationExtIEsValueValidateS1APExtensionContainer(fields s21.UserLocationInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.UserLocationInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s21.UserLocationInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUserLocationInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func ERABReleaseResponseIEValueERABIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable) s45.ERABReleaseResponseIEValueERABIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABReleaseResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s45.ERABReleaseResponseIEValueERABIEContainerListValueCodec {
		sealed := s45.ERABReleaseResponseIEValueERABIEContainerListValueCodec{}
		*s45.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABReleaseResponseIEValueERABIEContainerList, error) {
			value, err := (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABReleaseResponseIEValueERABIEContainerList(value), err
		}
		*s45.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABReleaseResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABReleaseResponseIEValueERABIEContainerList, options aper.DecodeState) (s45.ERABReleaseResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeERABReleaseResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABReleaseResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABReleaseResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupResponseIEValueERABIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable) s45.ERABSetupResponseIEValueERABIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABSetupResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s45.ERABSetupResponseIEValueERABIEContainerListValueCodec {
		sealed := s45.ERABSetupResponseIEValueERABIEContainerListValueCodec{}
		*s45.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABSetupResponseIEValueERABIEContainerList, error) {
			value, err := (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABSetupResponseIEValueERABIEContainerList(value), err
		}
		*s45.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABSetupResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABSetupResponseIEValueERABIEContainerList, options aper.DecodeState) (s45.ERABSetupResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABSetupResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABSetupResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportIEValueERABIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s45.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec{}
	}
	return func() s45.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec {
		sealed := s45.SecondaryRATDataUsageReportIEValueERABIEContainerListValueCodec{}
		*s45.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, error) {
			value, err := (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.SecondaryRATDataUsageReportIEValueERABIEContainerList(value), err
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s45.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextReleaseCompleteIEValueERABIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable) s45.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec{}
	}
	return func() s45.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec {
		sealed := s45.UEContextReleaseCompleteIEValueERABIEContainerListValueCodec{}
		*s45.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueERABIEContainerList, error) {
			value, err := (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextReleaseCompleteIEValueERABIEContainerList(value), err
		}
		*s45.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextReleaseCompleteIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s45.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextReleaseCompleteIEValueERABIEContainerList, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextReleaseCompleteIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextReleaseCompleteIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendRequestIEValueERABIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable) s45.UEContextSuspendRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextSuspendRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s45.UEContextSuspendRequestIEValueERABIEContainerListValueCodec {
		sealed := s45.UEContextSuspendRequestIEValueERABIEContainerListValueCodec{}
		*s45.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueERABIEContainerList, error) {
			value, err := (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextSuspendRequestIEValueERABIEContainerList(value), err
		}
		*s45.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextSuspendRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s45.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextSuspendRequestIEValueERABIEContainerList, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextSuspendRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextSuspendRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func V2XServicesAuthorizedExtIEsValueExtensionFieldTableCodec(table s00.V2XServicesAuthorizedExtIEsValueExtensionTable) s12.V2XServicesAuthorizedExtIEsExtFieldValueCodec {
	if !*s00.BridgeV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.V2XServicesAuthorizedExtIEsExtFieldValueCodec{}
	}
	return func() s12.V2XServicesAuthorizedExtIEsExtFieldValueCodec {
		sealed := s12.V2XServicesAuthorizedExtIEsExtFieldValueCodec{}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.V2XServicesAuthorizedExtIEsExtField, error) {
			var field s12.V2XServicesAuthorizedExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.V2XServicesAuthorizedExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.V2XServicesAuthorizedExtIEsExtField, options aper.DecodeState) (s12.V2XServicesAuthorizedExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.V2XServicesAuthorizedExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func V2XServicesAuthorizedExtIEsValueExtensionTableCodec(table s00.V2XServicesAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s12.V2XServicesAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s12.V2XServicesAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.V2XServicesAuthorizedExtIEsExtContainerValueCodec {
		sealed := s12.V2XServicesAuthorizedExtIEsExtContainerValueCodec{}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.V2XServicesAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.V2XServicesAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.V2XServicesAuthorizedExtIEsExtField
					if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.V2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.V2XServicesAuthorizedExtIEsExtContainer, options aper.DecodeState) (s12.V2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.V2XServicesAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupResponseIEValueIEFieldTableCodec(table s00.ERABSetupResponseIEValueIETable) s45.ERABSetupResponseIEFieldValueCodec {
	if !*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&table) {
		return s45.ERABSetupResponseIEFieldValueCodec{}
	}
	return func() s45.ERABSetupResponseIEFieldValueCodec {
		sealed := s45.ERABSetupResponseIEFieldValueCodec{}
		*s45.BridgeERABSetupResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABSetupResponseIEField, error) {
			var field s45.ERABSetupResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s45.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s45.BridgeERABSetupResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s45.ERABSetupResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s45.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s45.BridgeERABSetupResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s45.ERABSetupResponseIEField, options aper.DecodeState) (s45.ERABSetupResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s45.BridgeERABSetupResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s45.ERABSetupResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABSetupResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportIEValueIEFieldTableCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s45.SecondaryRATDataUsageReportIEFieldValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&table) {
		return s45.SecondaryRATDataUsageReportIEFieldValueCodec{}
	}
	return func() s45.SecondaryRATDataUsageReportIEFieldValueCodec {
		sealed := s45.SecondaryRATDataUsageReportIEFieldValueCodec{}
		*s45.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEField, error) {
			var field s45.SecondaryRATDataUsageReportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s45.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldEncode(&sealed) = func(field s45.SecondaryRATDataUsageReportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s45.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCapture(&sealed) = func(v s45.SecondaryRATDataUsageReportIEField, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s45.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldCompare(&sealed) = func(v s45.SecondaryRATDataUsageReportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeSecondaryRATDataUsageReportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextReleaseCompleteIEValueIEFieldTableCodec(table s00.UEContextReleaseCompleteIEValueIETable) s45.UEContextReleaseCompleteIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&table) {
		return s45.UEContextReleaseCompleteIEFieldValueCodec{}
	}
	return func() s45.UEContextReleaseCompleteIEFieldValueCodec {
		sealed := s45.UEContextReleaseCompleteIEFieldValueCodec{}
		*s45.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextReleaseCompleteIEField, error) {
			var field s45.UEContextReleaseCompleteIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s45.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldEncode(&sealed) = func(field s45.UEContextReleaseCompleteIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s45.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCapture(&sealed) = func(v s45.UEContextReleaseCompleteIEField, options aper.DecodeState) (s45.UEContextReleaseCompleteIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s45.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldCompare(&sealed) = func(v s45.UEContextReleaseCompleteIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextReleaseCompleteIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendRequestIEValueIEFieldTableCodec(table s00.UEContextSuspendRequestIEValueIETable) s45.UEContextSuspendRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextSuspendRequestIEValueIETableFieldBound(&table) {
		return s45.UEContextSuspendRequestIEFieldValueCodec{}
	}
	return func() s45.UEContextSuspendRequestIEFieldValueCodec {
		sealed := s45.UEContextSuspendRequestIEFieldValueCodec{}
		*s45.BridgeUEContextSuspendRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextSuspendRequestIEField, error) {
			var field s45.UEContextSuspendRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s45.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s45.BridgeUEContextSuspendRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s45.UEContextSuspendRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s45.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s45.BridgeUEContextSuspendRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s45.UEContextSuspendRequestIEField, options aper.DecodeState) (s45.UEContextSuspendRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s45.BridgeUEContextSuspendRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s45.UEContextSuspendRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextSuspendRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABReleaseResponseIEValueIETableCodec(table s00.ERABReleaseResponseIEValueIETable, bounds aper.ListBounds) s45.ERABReleaseResponseIEContainerValueCodec {
	if !*s00.BridgeERABReleaseResponseIEValueIETableFieldBound(&table) {
		return s45.ERABReleaseResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s45.ERABReleaseResponseIEContainerValueCodec {
		sealed := s45.ERABReleaseResponseIEContainerValueCodec{}
		*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABReleaseResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s45.ERABReleaseResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s45.ERABReleaseResponseIEField
					if err := s45.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s45.ERABReleaseResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s45.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s45.ERABReleaseResponseIEContainer, options aper.DecodeState) (s45.ERABReleaseResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s45.ERABReleaseResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupResponseIEValueIETableCodec(table s00.ERABSetupResponseIEValueIETable, bounds aper.ListBounds) s45.ERABSetupResponseIEContainerValueCodec {
	if !*s00.BridgeERABSetupResponseIEValueIETableFieldBound(&table) {
		return s45.ERABSetupResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s45.ERABSetupResponseIEContainerValueCodec {
		sealed := s45.ERABSetupResponseIEContainerValueCodec{}
		*s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABSetupResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s45.ERABSetupResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s45.ERABSetupResponseIEField
					if err := s45.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s45.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s45.ERABSetupResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s45.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s45.BridgeERABSetupResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s45.ERABSetupResponseIEContainer, options aper.DecodeState) (s45.ERABSetupResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABSetupResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s45.ERABSetupResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABSetupResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportIEValueIETableCodec(table s00.SecondaryRATDataUsageReportIEValueIETable, bounds aper.ListBounds) s45.SecondaryRATDataUsageReportIEContainerValueCodec {
	if !*s00.BridgeSecondaryRATDataUsageReportIEValueIETableFieldBound(&table) {
		return s45.SecondaryRATDataUsageReportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s45.SecondaryRATDataUsageReportIEContainerValueCodec {
		sealed := s45.SecondaryRATDataUsageReportIEContainerValueCodec{}
		*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s45.SecondaryRATDataUsageReportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s45.SecondaryRATDataUsageReportIEField
					if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&sealed) = func(fields s45.SecondaryRATDataUsageReportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCapture(&sealed) = func(v s45.SecondaryRATDataUsageReportIEContainer, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldCompare(&sealed) = func(v s45.SecondaryRATDataUsageReportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextReleaseCompleteIEValueIETableCodec(table s00.UEContextReleaseCompleteIEValueIETable, bounds aper.ListBounds) s45.UEContextReleaseCompleteIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseCompleteIEValueIETableFieldBound(&table) {
		return s45.UEContextReleaseCompleteIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s45.UEContextReleaseCompleteIEContainerValueCodec {
		sealed := s45.UEContextReleaseCompleteIEContainerValueCodec{}
		*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextReleaseCompleteIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s45.UEContextReleaseCompleteIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s45.UEContextReleaseCompleteIEField
					if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&sealed) = func(fields s45.UEContextReleaseCompleteIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCapture(&sealed) = func(v s45.UEContextReleaseCompleteIEContainer, options aper.DecodeState) (s45.UEContextReleaseCompleteIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldCompare(&sealed) = func(v s45.UEContextReleaseCompleteIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendRequestIEValueIETableCodec(table s00.UEContextSuspendRequestIEValueIETable, bounds aper.ListBounds) s45.UEContextSuspendRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextSuspendRequestIEValueIETableFieldBound(&table) {
		return s45.UEContextSuspendRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s45.UEContextSuspendRequestIEContainerValueCodec {
		sealed := s45.UEContextSuspendRequestIEContainerValueCodec{}
		*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextSuspendRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s45.UEContextSuspendRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s45.UEContextSuspendRequestIEField
					if err := s45.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s45.UEContextSuspendRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s45.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s45.UEContextSuspendRequestIEContainer, options aper.DecodeState) (s45.UEContextSuspendRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s45.UEContextSuspendRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABReleaseResponseIEValueProtocolErrorIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable) s45.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s45.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s45.ERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s45.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeERABReleaseResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupResponseIEValueProtocolErrorIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable) s45.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s45.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s45.ERABSetupResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s45.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABSetupResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s45.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABSetupResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable) s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodec{}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList(value), err
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s45.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextReleaseCompleteIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable) s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodec{}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList(value), err
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s45.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable) s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s45.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ERABReleaseResponseIEValueProtocolIEContainerListCodec(table s00.ERABReleaseResponseIEValueIETable, bounds aper.ListBounds) s45.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec {
	codec := ERABReleaseResponseIEValueIETableCodec(table, bounds)
	if *s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s45.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s45.ERABReleaseResponseIEValueProtocolIEContainerListValueCodec{}
		*s45.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABReleaseResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABReleaseResponseIEValueProtocolIEContainerList(value), err
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABReleaseResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABReleaseResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABReleaseResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABReleaseResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s45.ERABReleaseResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABReleaseResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABReleaseResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ERABSetupResponseIEValueProtocolIEContainerListCodec(table s00.ERABSetupResponseIEValueIETable, bounds aper.ListBounds) s45.ERABSetupResponseIEValueProtocolIEContainerListValueCodec {
	codec := ERABSetupResponseIEValueIETableCodec(table, bounds)
	if *s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.ERABSetupResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s45.ERABSetupResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s45.ERABSetupResponseIEValueProtocolIEContainerListValueCodec{}
		*s45.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.ERABSetupResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.ERABSetupResponseIEValueProtocolIEContainerList(value), err
		}
		*s45.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.ERABSetupResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeERABSetupResponseIEContainerValueCodecFieldEncode(&codec))(s45.ERABSetupResponseIEContainer(value), fresh, budget)
		}
		*s45.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.ERABSetupResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s45.ERABSetupResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.ERABSetupResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeERABSetupResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func SecondaryRATDataUsageReportIEValueProtocolIEContainerListCodec(table s00.SecondaryRATDataUsageReportIEValueIETable, bounds aper.ListBounds) s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec {
	codec := SecondaryRATDataUsageReportIEValueIETableCodec(table, bounds)
	if *s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec {
		sealed := s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodec{}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, error) {
			value, err := (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList(value), err
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeSecondaryRATDataUsageReportIEContainerValueCodecFieldEncode(&codec))(s45.SecondaryRATDataUsageReportIEContainer(value), fresh, budget)
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, options aper.DecodeState) (s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeSecondaryRATDataUsageReportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextReleaseCompleteIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseCompleteIEValueIETable, bounds aper.ListBounds) s45.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseCompleteIEValueIETableCodec(table, bounds)
	if *s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s45.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec {
		sealed := s45.UEContextReleaseCompleteIEValueProtocolIEContainerListValueCodec{}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, error) {
			value, err := (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextReleaseCompleteIEValueProtocolIEContainerList(value), err
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextReleaseCompleteIEContainerValueCodecFieldEncode(&codec))(s45.UEContextReleaseCompleteIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, options aper.DecodeState) (s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextReleaseCompleteIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendRequestIEValueProtocolIEContainerListCodec(table s00.UEContextSuspendRequestIEValueIETable, bounds aper.ListBounds) s45.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextSuspendRequestIEValueIETableCodec(table, bounds)
	if *s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s45.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s45.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s45.UEContextSuspendRequestIEValueProtocolIEContainerListValueCodec{}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s45.UEContextSuspendRequestIEValueProtocolIEContainerList(value), err
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s45.UEContextSuspendRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s45.BridgeUEContextSuspendRequestIEContainerValueCodecFieldEncode(&codec))(s45.UEContextSuspendRequestIEContainer(value), fresh, budget)
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s45.UEContextSuspendRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s45.UEContextSuspendRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s45.UEContextSuspendRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEContextSuspendRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eRABReleaseResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABReleaseResponseIEValue].
type ERABReleaseResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s45.ERABReleaseResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s45.ERABReleaseResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// eRABSetupResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ERABSetupResponseIEValue].
type ERABSetupResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s45.ERABSetupResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s45.ERABSetupResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(v *s45.ERABSetupResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s45.BridgeERABSetupResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s45.BridgeERABSetupResponseIEFieldFieldReplay(v), *s45.BridgeERABSetupResponseIEFieldFieldWithoutReplay(v))
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(v *s45.ERABSetupResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s45.BridgeERABSetupResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s45.BridgeERABSetupResponseIEFieldFieldReplay(v), *s45.BridgeERABSetupResponseIEFieldFieldWithoutReplay(v))
}
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v *PathSwitchRequestAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}

// secondaryRATDataUsageReportIEValueProtocolOpenValue is the concrete protocolOpenValue[SecondaryRATDataUsageReportIEValue].
type SecondaryRATDataUsageReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s45.SecondaryRATDataUsageReportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s45.SecondaryRATDataUsageReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(v *s45.SecondaryRATDataUsageReportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s45.BridgeSecondaryRATDataUsageReportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s45.BridgeSecondaryRATDataUsageReportIEFieldFieldReplay(v), *s45.BridgeSecondaryRATDataUsageReportIEFieldFieldWithoutReplay(v))
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(v *s45.SecondaryRATDataUsageReportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s45.BridgeSecondaryRATDataUsageReportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s45.BridgeSecondaryRATDataUsageReportIEFieldFieldReplay(v), *s45.BridgeSecondaryRATDataUsageReportIEFieldFieldWithoutReplay(v))
}

// uEContextReleaseCompleteIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseCompleteIEValue].
type UEContextReleaseCompleteIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s45.UEContextReleaseCompleteIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s45.UEContextReleaseCompleteIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(v *s45.UEContextReleaseCompleteIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s45.BridgeUEContextReleaseCompleteIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s45.BridgeUEContextReleaseCompleteIEFieldFieldReplay(v), *s45.BridgeUEContextReleaseCompleteIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(v *s45.UEContextReleaseCompleteIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s45.BridgeUEContextReleaseCompleteIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s45.BridgeUEContextReleaseCompleteIEFieldFieldReplay(v), *s45.BridgeUEContextReleaseCompleteIEFieldFieldWithoutReplay(v))
}

// uEContextSuspendRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextSuspendRequestIEValue].
type UEContextSuspendRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s45.UEContextSuspendRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s45.UEContextSuspendRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(v *s45.UEContextSuspendRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s45.BridgeUEContextSuspendRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s45.BridgeUEContextSuspendRequestIEFieldFieldReplay(v), *s45.BridgeUEContextSuspendRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(v *s45.UEContextSuspendRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s45.BridgeUEContextSuspendRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s45.BridgeUEContextSuspendRequestIEFieldFieldReplay(v), *s45.BridgeUEContextSuspendRequestIEFieldFieldWithoutReplay(v))
}

// userLocationInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UserLocationInformationExtIEsValue].
type UserLocationInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.UserLocationInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.UserLocationInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionField(v *s12.V2XServicesAuthorizedExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeV2XServicesAuthorizedExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionField(v *s12.V2XServicesAuthorizedExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeV2XServicesAuthorizedExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldReplay(v), *s12.BridgeV2XServicesAuthorizedExtIEsExtFieldFieldWithoutReplay(v))
}

// V2XServicesAuthorizedAPERValue is the concrete APERValue[V2XServicesAuthorized].
type V2XServicesAuthorizedAPERValue struct {
	context s00.BridgeCodecContext
	Value   V2XServicesAuthorized

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v V2XServicesAuthorizedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v V2XServicesAuthorizedAPERValue) WithoutReplay() V2XServicesAuthorizedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABReleaseResponseAPERValue is the concrete APERValue[ERABReleaseResponse].
type ERABReleaseResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABReleaseResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABReleaseResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABReleaseResponseAPERValue) WithoutReplay() ERABReleaseResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABSetupResponseAPERValue is the concrete APERValue[ERABSetupResponse].
type ERABSetupResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ERABSetupResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABSetupResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABSetupResponseAPERValue) WithoutReplay() ERABSetupResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageReportAPERValue is the concrete APERValue[SecondaryRATDataUsageReport].
type SecondaryRATDataUsageReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   SecondaryRATDataUsageReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageReportAPERValue) WithoutReplay() SecondaryRATDataUsageReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCompleteAPERValue is the concrete APERValue[UEContextReleaseComplete].
type UEContextReleaseCompleteAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseComplete

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCompleteAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCompleteAPERValue) WithoutReplay() UEContextReleaseCompleteAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendRequestAPERValue is the concrete APERValue[UEContextSuspendRequest].
type UEContextSuspendRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextSuspendRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendRequestAPERValue) WithoutReplay() UEContextSuspendRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUserLocationInformationExtIEsValueValidateS1APIEContainer(fields s21.UserLocationInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s21.BridgeUserLocationInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s21.BridgeUserLocationInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s21.BridgeUserLocationInformationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeERABReleaseResponseIEValueCompareS1APERABIEContainerList(v *s45.ERABReleaseResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APERABIEContainerList(v *s45.ERABSetupResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APERABIEContainerList(v *s45.ERABSetupResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList) (PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerList is the concrete ERABIEContainerList[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueERABIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APERABIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APERABIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) New(value UEContextModificationRequestIEValueERABIEContainerList) (UEContextModificationRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueERABIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCompleteIEValueCaptureS1APERABIEContainerList(v *s45.UEContextReleaseCompleteIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APERABIEContainerList(v *s45.UEContextReleaseCompleteIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APERABIEContainerList(v *s45.UEContextSuspendRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APERABIEContainerList(v *s45.UEContextSuspendRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, error)
	encode  func(PathSwitchRequestAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEField, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) New(value PathSwitchRequestAcknowledgeIEField) (PathSwitchRequestAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEField, error)
	encode  func(UEContextModificationRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEField, aper.DecodeState) (UEContextModificationRequestIEField, aper.Snapshot)
	compare func(UEContextModificationRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEFieldValueCodec) New(value UEContextModificationRequestIEField) (UEContextModificationRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEFieldValueCodec) EncodeAPER(value UEContextModificationRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestIEFieldValueCodec) encodeBudgetValue(value UEContextModificationRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEFieldValueCodec) encodeChanged(value UEContextModificationRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, error)
	encode  func(PathSwitchRequestAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEContainer, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) New(value PathSwitchRequestAcknowledgeIEContainer) (PathSwitchRequestAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEContainer, error)
	encode  func(UEContextModificationRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEContainer, aper.DecodeState) (UEContextModificationRequestIEContainer, aper.Snapshot)
	compare func(UEContextModificationRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEContainerValueCodec) New(value UEContextModificationRequestIEContainer) (UEContextModificationRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEContainerValueCodec) EncodeAPER(value UEContextModificationRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestIEContainerValueCodec) encodeBudgetValue(value UEContextModificationRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEContainerValueCodec) encodeChanged(value UEContextModificationRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s45.ERABReleaseResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s45.ERABSetupResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolErrorIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolErrorIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationRequestIEValueProtocolErrorIEContainerList) (UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueProtocolErrorIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolErrorIEContainerList(v *s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolErrorIEContainerList(v *s45.UEContextReleaseCompleteIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s45.UEContextSuspendRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainerList(v *s45.ERABReleaseResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainerList(v *s45.ERABSetupResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainerList(v *s45.ERABSetupResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainerList(v *s45.SecondaryRATDataUsageReportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationRequestIEValueProtocolIEContainerList) (UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueProtocolIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainerList(v *s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainerList(v *s45.UEContextReleaseCompleteIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainerList(v *s45.UEContextSuspendRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainerList(v *s45.UEContextSuspendRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABReleaseResponseIEValueCompareS1APProtocolIESingleContainer(v *s45.ERABReleaseResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeERABReleaseResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeERABSetupResponseIEValueCaptureS1APProtocolIESingleContainer(v *s45.ERABSetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeERABSetupResponseIEValueCompareS1APProtocolIESingleContainer(v *s45.ERABSetupResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer = PathSwitchRequestAcknowledgeIEField

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIESingleContainer(v *s45.SecondaryRATDataUsageReportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIESingleContainer(v *s45.SecondaryRATDataUsageReportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueProtocolIESingleContainer = UEContextModificationRequestIEField

func BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIESingleContainer(v *s45.UEContextReleaseCompleteIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIESingleContainer(v *s45.UEContextReleaseCompleteIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIESingleContainer(v *s45.UEContextSuspendRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIESingleContainer(v *s45.UEContextSuspendRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEFieldAPERValue is the concrete APERValue[ProtocolIEField[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEFieldAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEFieldAPERValue) WithoutReplay() UEContextModificationRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEContainerAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEContainerAPERValue) WithoutReplay() UEContextModificationRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[PathSwitchRequestAcknowledgeIEValue]].
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextModificationRequestIEValue]].
type UEContextModificationRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABReleaseResponse(v *ERABReleaseResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeERABReleaseResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABReleaseResponse(v *ERABReleaseResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeERABReleaseResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABSetupResponse(v *ERABSetupResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABSetupResponse(v *ERABSetupResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeERABSetupResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPathSwitchRequestAcknowledgeIEValue(v *PathSwitchRequestAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(95):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULList == nil)
				if v.rowERABToBeSwitchedULList != nil {
					s25.BridgeCaptureS1APERABToBeSwitchedULList(v.rowERABToBeSwitchedULList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s24.BridgeCaptureS1APERABList(v.rowERABToBeReleasedList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s28.BridgeCaptureS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s00.BridgeCaptureS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s00.BridgeCaptureS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s00.BridgeCaptureS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s00.BridgeCaptureS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s42.BridgeCaptureS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(341):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedList == nil)
				if v.rowERABToBeUpdatedList != nil {
					s30.BridgeCaptureS1APERABToBeUpdatedList(v.rowERABToBeUpdatedList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s00.BridgeCaptureS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) PathSwitchRequestAcknowledgeIEValue {
	BridgeCaptureS1APPathSwitchRequestAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPathSwitchRequestAcknowledgeIEValue(v *PathSwitchRequestAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(95):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULList == nil)
				if v.rowERABToBeSwitchedULList != nil {
					s25.BridgeCompareS1APERABToBeSwitchedULList(v.rowERABToBeSwitchedULList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s24.BridgeCompareS1APERABList(v.rowERABToBeReleasedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s28.BridgeCompareS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s02.BridgeCompareS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s02.BridgeCompareS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s02.BridgeCompareS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s02.BridgeCompareS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s42.BridgeCompareS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s02.BridgeCompareS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(341):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedList == nil)
				if v.rowERABToBeUpdatedList != nil {
					s30.BridgeCompareS1APERABToBeUpdatedList(v.rowERABToBeUpdatedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s07.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPathSwitchRequestAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSecondaryRATDataUsageReport(v *SecondaryRATDataUsageReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecondaryRATDataUsageReport(v *SecondaryRATDataUsageReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeSecondaryRATDataUsageReportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationRequestIEValue(v *UEContextModificationRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s00.BridgeCaptureS1APSecurityKey(v.rowSecurityKey, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(106):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriberProfileIDforRFP == nil)
				if v.rowSubscriberProfileIDforRFP != nil {
					s00.BridgeCaptureS1APSubscriberProfileIDforRFP(v.rowSubscriberProfileIDforRFP, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(108):
			{
				f := s.Begin()
				s.Bool(v.rowCSFallbackIndicator == nil)
				if v.rowCSFallbackIndicator != nil {
					s00.BridgeCaptureS1APCSFallbackIndicator(v.rowCSFallbackIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(159):
			{
				f := s.Begin()
				s.Bool(v.rowRegisteredLAI == nil)
				if v.rowRegisteredLAI != nil {
					s18.BridgeCaptureS1APLAI(v.rowRegisteredLAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(187):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalCSFallbackIndicator == nil)
				if v.rowAdditionalCSFallbackIndicator != nil {
					s00.BridgeCaptureS1APAdditionalCSFallbackIndicator(v.rowAdditionalCSFallbackIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(243):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationNotPossible == nil)
				if v.rowSRVCCOperationNotPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationNotPossible(v.rowSRVCCOperationNotPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s00.BridgeCaptureS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s00.BridgeCaptureS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s00.BridgeCaptureS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationRequestIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationRequestIEValue {
	BridgeCaptureS1APUEContextModificationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationRequestIEValue(v *UEContextModificationRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s07.BridgeCompareS1APSecurityKey(v.rowSecurityKey, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(106):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriberProfileIDforRFP == nil)
				if v.rowSubscriberProfileIDforRFP != nil {
					s07.BridgeCompareS1APSubscriberProfileIDforRFP(v.rowSubscriberProfileIDforRFP, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s35.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(108):
			{
				f := s.Begin()
				s.Bool(v.rowCSFallbackIndicator == nil)
				if v.rowCSFallbackIndicator != nil {
					s02.BridgeCompareS1APCSFallbackIndicator(v.rowCSFallbackIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(159):
			{
				f := s.Begin()
				s.Bool(v.rowRegisteredLAI == nil)
				if v.rowRegisteredLAI != nil {
					s18.BridgeCompareS1APLAI(v.rowRegisteredLAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(187):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalCSFallbackIndicator == nil)
				if v.rowAdditionalCSFallbackIndicator != nil {
					s02.BridgeCompareS1APAdditionalCSFallbackIndicator(v.rowAdditionalCSFallbackIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s06.BridgeCompareS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(243):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationNotPossible == nil)
				if v.rowSRVCCOperationNotPossible != nil {
					s06.BridgeCompareS1APSRVCCOperationNotPossible(v.rowSRVCCOperationNotPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s02.BridgeCompareS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s02.BridgeCompareS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s02.BridgeCompareS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s19.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s07.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextReleaseComplete(v *UEContextReleaseComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseComplete(v *UEContextReleaseComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCompleteIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextSuspendRequest(v *UEContextSuspendRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextSuspendRequest(v *UEContextSuspendRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APV2XServicesAuthorized(v *V2XServicesAuthorized, s *aper.SemanticCapture) {
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
	BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APV2XServicesAuthorized(v *V2XServicesAuthorized, s *aper.SemanticComparison) {
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
	BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// V2XServicesAuthorized represents the ASN.1 type V2XServicesAuthorized (SEQUENCE).
type V2XServicesAuthorized struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	VehicleUE         *s00.VehicleUE                              `asn1:"tag:0,context,implicit,optional" json:"VehicleUE,omitempty"`
	PedestrianUE      *s00.PedestrianUE                           `asn1:"tag:1,context,implicit,optional" json:"PedestrianUE,omitempty"`
	IEExtensions      s12.V2XServicesAuthorizedExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes V2XServicesAuthorized to APER format.
func (v *V2XServicesAuthorized) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *V2XServicesAuthorized) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
				if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes V2XServicesAuthorized from APER format.
func (v *V2XServicesAuthorized) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes V2XServicesAuthorized with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *V2XServicesAuthorized) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	bb.EnterComponent("V2XServicesAuthorized")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	padding, err := aper.CaptureFinalBits(bb, "V2XServicesAuthorized")
	if err != nil {
		return runtime.WrapDecodePath(err, "V2XServicesAuthorized")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *V2XServicesAuthorized) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = V2XServicesAuthorized{}
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
		tmp_ieextensions := make(s12.V2XServicesAuthorizedExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.V2XServicesAuthorizedExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *V2XServicesAuthorized) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "V2XServicesAuthorized", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "V2XServicesAuthorized", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v V2XServicesAuthorized) WithoutReplay() V2XServicesAuthorized {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero V2XServicesAuthorized
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *V2XServicesAuthorized) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *V2XServicesAuthorized) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *V2XServicesAuthorized) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("V2XServicesAuthorized.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *V2XServicesAuthorized) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "V2XServicesAuthorized")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *V2XServicesAuthorized) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "V2XServicesAuthorized")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APV2XServicesAuthorized(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "V2XServicesAuthorized")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "V2XServicesAuthorized")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *V2XServicesAuthorized) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "V2XServicesAuthorized")
}
func (v *V2XServicesAuthorized) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "V2XServicesAuthorized")
}
func (v *V2XServicesAuthorized) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APV2XServicesAuthorized(v, &s)
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
func (v *V2XServicesAuthorized) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *V2XServicesAuthorized) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *V2XServicesAuthorized) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "V2XServicesAuthorized")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded V2XServicesAuthorized
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APV2XServicesAuthorized(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = V2XServicesAuthorized{}
		return report, aper.OperationError(err, "V2XServicesAuthorized")
	}
	*v = decoded
	return report, aper.OperationError(nil, "V2XServicesAuthorized")
}

// ERABSetupResponse represents the ASN.1 type E-RABSetupResponse (SEQUENCE).
type ERABSetupResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s45.ERABSetupResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABReleaseResponse represents the ASN.1 type E-RABReleaseResponse (SEQUENCE).
type ERABReleaseResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s45.ERABReleaseResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextReleaseComplete represents the ASN.1 type UEContextReleaseComplete (SEQUENCE).
type UEContextReleaseComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s45.UEContextReleaseCompleteIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextSuspendRequest represents the ASN.1 type UEContextSuspendRequest (SEQUENCE).
type UEContextSuspendRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s45.UEContextSuspendRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SecondaryRATDataUsageReport represents the ASN.1 type SecondaryRATDataUsageReport (SEQUENCE).
type SecondaryRATDataUsageReport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s45.SecondaryRATDataUsageReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                       `asn1:"-" json:"-"`
	extCount         int64                                      `asn1:"-" json:"-"`
	extPresent       []bool                                     `asn1:"-" json:"-"`
	extData          [][]byte                                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ERABSetupResponse to APER format.
func (v *ERABSetupResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABSetupResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s45.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABSetupResponse from APER format.
func (v *ERABSetupResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABSetupResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABSetupResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	bb.EnterComponent("ERABSetupResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABSetupResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABSetupResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABSetupResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABSetupResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s45.ERABSetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s45.ERABSetupResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s45.BridgeERABSetupResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ERABReleaseResponse to APER format.
func (v *ERABReleaseResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ERABReleaseResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s45.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ERABReleaseResponse from APER format.
func (v *ERABReleaseResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ERABReleaseResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ERABReleaseResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	bb.EnterComponent("ERABReleaseResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABReleaseResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABReleaseResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ERABReleaseResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABReleaseResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s45.ERABReleaseResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s45.ERABReleaseResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s45.BridgeERABReleaseResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextReleaseComplete to APER format.
func (v *UEContextReleaseComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseComplete) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextReleaseComplete from APER format.
func (v *UEContextReleaseComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextReleaseComplete with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextReleaseComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	bb.EnterComponent("UEContextReleaseComplete")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseComplete")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseComplete")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextReleaseComplete) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseComplete{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s45.UEContextReleaseCompleteIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s45.UEContextReleaseCompleteIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextSuspendRequest to APER format.
func (v *UEContextSuspendRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextSuspendRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s45.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextSuspendRequest from APER format.
func (v *UEContextSuspendRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextSuspendRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextSuspendRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	bb.EnterComponent("UEContextSuspendRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextSuspendRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextSuspendRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s45.UEContextSuspendRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s45.UEContextSuspendRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s45.BridgeUEContextSuspendRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SecondaryRATDataUsageReport to APER format.
func (v *SecondaryRATDataUsageReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SecondaryRATDataUsageReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SecondaryRATDataUsageReport from APER format.
func (v *SecondaryRATDataUsageReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecondaryRATDataUsageReport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecondaryRATDataUsageReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	bb.EnterComponent("SecondaryRATDataUsageReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SecondaryRATDataUsageReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SecondaryRATDataUsageReport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s45.SecondaryRATDataUsageReportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s45.SecondaryRATDataUsageReportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ERABReleaseResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABReleaseResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABReleaseResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABReleaseResponse) WithoutReplay() ERABReleaseResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABReleaseResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABSetupResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABSetupResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABSetupResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABSetupResponse) WithoutReplay() ERABSetupResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABSetupResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecondaryRATDataUsageReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecondaryRATDataUsageReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecondaryRATDataUsageReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecondaryRATDataUsageReport) WithoutReplay() SecondaryRATDataUsageReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecondaryRATDataUsageReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextReleaseComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseComplete) WithoutReplay() UEContextReleaseComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseComplete
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextSuspendRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextSuspendRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextSuspendRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextSuspendRequest) WithoutReplay() UEContextSuspendRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextSuspendRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ERABReleaseResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABReleaseResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABReleaseResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABReleaseResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ERABSetupResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ERABSetupResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ERABSetupResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ERABSetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SecondaryRATDataUsageReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SecondaryRATDataUsageReport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SecondaryRATDataUsageReport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SecondaryRATDataUsageReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextReleaseComplete) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseComplete) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseComplete) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseComplete.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextSuspendRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextSuspendRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextSuspendRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABReleaseResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABReleaseResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABReleaseResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABReleaseResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABReleaseResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABReleaseResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABReleaseResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABReleaseResponse")
}
func (v *ERABReleaseResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABReleaseResponse")
}
func (v *ERABReleaseResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABReleaseResponse(v, &s)
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
func (v *ERABReleaseResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABReleaseResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABSetupResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABSetupResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABSetupResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABSetupResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABSetupResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABSetupResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABSetupResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABSetupResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABSetupResponse")
}
func (v *ERABSetupResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABSetupResponse")
}
func (v *ERABSetupResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABSetupResponse(v, &s)
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
func (v *ERABSetupResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABSetupResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SecondaryRATDataUsageReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecondaryRATDataUsageReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecondaryRATDataUsageReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecondaryRATDataUsageReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecondaryRATDataUsageReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func (v *SecondaryRATDataUsageReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func (v *SecondaryRATDataUsageReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecondaryRATDataUsageReport(v, &s)
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
func (v *SecondaryRATDataUsageReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecondaryRATDataUsageReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextReleaseComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseComplete")
}
func (v *UEContextReleaseComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseComplete")
}
func (v *UEContextReleaseComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseComplete(v, &s)
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
func (v *UEContextReleaseComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextSuspendRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextSuspendRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextSuspendRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextSuspendRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextSuspendRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextSuspendRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextSuspendRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextSuspendRequest")
}
func (v *UEContextSuspendRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextSuspendRequest")
}
func (v *UEContextSuspendRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextSuspendRequest(v, &s)
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
func (v *UEContextSuspendRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextSuspendRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABReleaseResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABReleaseResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABReleaseResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABReleaseResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABReleaseResponse{}
		return report, aper.OperationError(err, "ERABReleaseResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABReleaseResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABSetupResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABSetupResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABSetupResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABSetupResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABSetupResponse{}
		return report, aper.OperationError(err, "ERABSetupResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABSetupResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecondaryRATDataUsageReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecondaryRATDataUsageReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecondaryRATDataUsageReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecondaryRATDataUsageReport{}
		return report, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecondaryRATDataUsageReport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextReleaseComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseComplete{}
		return report, aper.OperationError(err, "UEContextReleaseComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextSuspendRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextSuspendRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextSuspendRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextSuspendRequest{}
		return report, aper.OperationError(err, "UEContextSuspendRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextSuspendRequest")
}

type PathSwitchRequestAcknowledgeIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowENBUES1APID                            *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate              *s35.UEAggregateMaximumBitrate
	rowERABToBeSwitchedULList                 *s17.ERABToBeSwitchedULList
	rowERABToBeReleasedList                   *s16.ERABList
	rowSecurityContext                        *s28.SecurityContext
	rowCriticalityDiagnostics                 *s22.CriticalityDiagnostics
	rowMMEUES1APID2                           *s00.MMEUES1APID
	rowCSGMembershipStatus                    *s00.CSGMembershipStatus
	rowProSeAuthorized                        *s20.ProSeAuthorized
	rowUEUserPlaneCIoTSupportIndicator        *s00.UEUserPlaneCIoTSupportIndicator
	rowV2XServicesAuthorized                  *V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate      *s37.UESidelinkAggregateMaximumBitrate
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowNRUESecurityCapabilities               *s19.NRUESecurityCapabilities
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowAerialUEsubscriptionInformation        *s00.AerialUEsubscriptionInformation
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowSubscriptionBasedUEDifferentiationInfo *s30.SubscriptionBasedUEDifferentiationInfo
	rowHandoverRestrictionList                *s42.HandoverRestrictionList
	rowAdditionalRRMPriorityIndex             *s00.AdditionalRRMPriorityIndex
	rowNRV2XServicesAuthorized                *s19.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate    *s19.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                       *s24.PC5QoSParameters
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowUESecurityCapabilities                 *s37.UESecurityCapabilities
	rowERABToBeUpdatedList                    *s29.ERABToBeUpdatedList
	rowTimeRefDistribution                    *s00.TimeRefDistribution
}

func (v PathSwitchRequestAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(95):
		return v.rowERABToBeSwitchedULList != nil
	case s00.ProtocolIEID(33):
		return v.rowERABToBeReleasedList != nil
	case s00.ProtocolIEID(40):
		return v.rowSecurityContext != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(158):
		return v.rowMMEUES1APID2 != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(195):
		return v.rowProSeAuthorized != nil
	case s00.ProtocolIEID(241):
		return v.rowUEUserPlaneCIoTSupportIndicator != nil
	case s00.ProtocolIEID(240):
		return v.rowV2XServicesAuthorized != nil
	case s00.ProtocolIEID(248):
		return v.rowUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(277):
		return v.rowAerialUEsubscriptionInformation != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(41):
		return v.rowHandoverRestrictionList != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(306):
		return v.rowNRV2XServicesAuthorized != nil
	case s00.ProtocolIEID(307):
		return v.rowNRUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(308):
		return v.rowPC5QoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(341):
		return v.rowERABToBeUpdatedList != nil
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PathSwitchRequestAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *PathSwitchRequestAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PathSwitchRequestAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs"}}
}
func (PathSwitchRequestAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(95):
		return aper.UnknownSelector
	case s00.ProtocolIEID(33):
		return aper.UnknownSelector
	case s00.ProtocolIEID(40):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(158):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(195):
		return aper.UnknownSelector
	case s00.ProtocolIEID(241):
		return aper.UnknownSelector
	case s00.ProtocolIEID(240):
		return aper.UnknownSelector
	case s00.ProtocolIEID(248):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(277):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(41):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(306):
		return aper.UnknownSelector
	case s00.ProtocolIEID(307):
		return aper.UnknownSelector
	case s00.ProtocolIEID(308):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(341):
		return aper.UnknownSelector
	case s00.ProtocolIEID(355):
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
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
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
	case s00.ProtocolIEID(270):
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
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeSwitchedULList returns the selected ERABToBeSwitchedULList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeSwitchedULList() (*s17.ERABToBeSwitchedULList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(95) || v.rowERABToBeSwitchedULList == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedULList, true
}

// AsERABToBeReleasedList returns the selected ERABToBeReleasedList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeReleasedList() (*s16.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(33) || v.rowERABToBeReleasedList == nil {
		return nil, false
	}
	return v.rowERABToBeReleasedList, true
}

// AsSecurityContext returns the selected SecurityContext value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsSecurityContext() (*s28.SecurityContext, bool) {
	if v == nil || v.id != s00.ProtocolIEID(40) || v.rowSecurityContext == nil {
		return nil, false
	}
	return v.rowSecurityContext, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsMMEUES1APID2 returns the selected MMEUES1APID2 value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsMMEUES1APID2() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(158) || v.rowMMEUES1APID2 == nil {
		return nil, false
	}
	return v.rowMMEUES1APID2, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsProSeAuthorized returns the selected ProSeAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsProSeAuthorized() (*s20.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}

// AsUEUserPlaneCIoTSupportIndicator returns the selected UEUserPlaneCIoTSupportIndicator value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUEUserPlaneCIoTSupportIndicator() (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(241) || v.rowUEUserPlaneCIoTSupportIndicator == nil {
		return nil, false
	}
	return v.rowUEUserPlaneCIoTSupportIndicator, true
}

// AsV2XServicesAuthorized returns the selected V2XServicesAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsV2XServicesAuthorized() (*V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}

// AsUESidelinkAggregateMaximumBitrate returns the selected UESidelinkAggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUESidelinkAggregateMaximumBitrate() (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsAerialUEsubscriptionInformation returns the selected AerialUEsubscriptionInformation value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsHandoverRestrictionList returns the selected HandoverRestrictionList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsHandoverRestrictionList() (*s42.HandoverRestrictionList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(41) || v.rowHandoverRestrictionList == nil {
		return nil, false
	}
	return v.rowHandoverRestrictionList, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsNRV2XServicesAuthorized returns the selected NRV2XServicesAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRV2XServicesAuthorized() (*s19.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}

// AsNRUESidelinkAggregateMaximumBitrate returns the selected NRUESidelinkAggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}

// AsPC5QoSParameters returns the selected PC5QoSParameters value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsPC5QoSParameters() (*s24.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsERABToBeUpdatedList returns the selected ERABToBeUpdatedList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeUpdatedList() (*s29.ERABToBeUpdatedList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(341) || v.rowERABToBeUpdatedList == nil {
		return nil, false
	}
	return v.rowERABToBeUpdatedList, true
}

// AsTimeRefDistribution returns the selected TimeRefDistribution value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v PathSwitchRequestAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PathSwitchRequestAcknowledgeIEValue, error) {
	out := PathSwitchRequestAcknowledgeIEValue{id: id}
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
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAggregateMaximumBitrate
		child := scope
		if err := s35.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s35.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s35.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(95):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s41.BridgeUnmarshalAPERERABToBeSwitchedULListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedULList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSwitchedULList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(33):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeReleasedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeReleasedList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(40):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.SecurityContext
		child := scope
		if err := s28.BridgeSecurityContextMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityContext:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityContext")
		if err != nil {
			return out, err
		}
		*s28.BridgeSecurityContextFieldPerPadding(&value) = padding
		*s28.BridgeSecurityContextFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeSecurityContextFieldReceivedBytes(&value))
		*s28.BridgeSecurityContextFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityContext = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(158):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID2:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID2 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(146):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
		value := s00.CSGMembershipStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSGMembershipStatus = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.ProSeAuthorized
		child := scope
		if err := s20.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s20.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s20.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s20.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowProSeAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(241):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UEUserPlaneCIoTSupportIndicator"})
		value := s00.UEUserPlaneCIoTSupportIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEUserPlaneCIoTSupportIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEUserPlaneCIoTSupportIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(240):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value V2XServicesAuthorized
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(251):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnhancedCoverageRestricted"})
		value := s00.EnhancedCoverageRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EnhancedCoverageRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEnhancedCoverageRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(269):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESecurityCapabilities
		child := scope
		if err := s19.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s19.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s19.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(271):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBRestricted"})
		value := s00.CEModeBRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(277):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AerialUEsubscriptionInformation"})
		value := s00.AerialUEsubscriptionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AerialUEsubscriptionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAerialUEsubscriptionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(283):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PendingDataIndication"})
		value := s00.PendingDataIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PendingDataIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPendingDataIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(278):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s30.SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(&value) = padding
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(&value))
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(41):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s42.HandoverRestrictionList
		child := scope
		if err := s42.BridgeHandoverRestrictionListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "HandoverRestrictionList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRestrictionList")
		if err != nil {
			return out, err
		}
		*s42.BridgeHandoverRestrictionListFieldPerPadding(&value) = padding
		*s42.BridgeHandoverRestrictionListFieldReceived(&value) = true
		raw.RetainContents(s42.BridgeHandoverRestrictionListFieldReceivedBytes(&value))
		*s42.BridgeHandoverRestrictionListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowHandoverRestrictionList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(299):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.AdditionalRRMPriorityIndex, error) {
			var v struct {
				Value s00.AdditionalRRMPriorityIndex
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
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
		out.rowAdditionalRRMPriorityIndex = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(306):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRV2XServicesAuthorized
		child := scope
		if err := s19.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s19.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s19.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s24.PC5QoSParameters
		child := scope
		if err := s24.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s24.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s24.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s24.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s24.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPC5QoSParameters = &value
		raw.RetainContents(&out.received)
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
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESecurityCapabilities
		child := scope
		if err := s37.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s37.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s37.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(341):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s41.BridgeUnmarshalAPERERABToBeUpdatedListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeUpdatedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeUpdatedList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(355):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeRefDistribution"})
		value := s00.TimeRefDistribution(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeRefDistribution:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeRefDistribution = &value
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
func (v PathSwitchRequestAcknowledgeIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v PathSwitchRequestAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(95):
		if v.rowERABToBeSwitchedULList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeSwitchedULList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s41.ERABToBeSwitchedULListComplete{Value: *v.rowERABToBeSwitchedULList}
		candidate, err := s41.BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(33):
		if v.rowERABToBeReleasedList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeReleasedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABListComplete{Value: *v.rowERABToBeReleasedList}
		candidate, err := s39.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(40):
		if v.rowSecurityContext == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-SecurityContext:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSecurityContextMethodMarshalAPERBudget(v.rowSecurityContext, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(158):
		if v.rowMMEUES1APID2 == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID-2:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID2), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CSGMembershipStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSGMembershipStatus), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(241):
		if v.rowUEUserPlaneCIoTSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UEUserPlaneCIoTSupportIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUEUserPlaneCIoTSupportIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(240):
		if v.rowV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowV2XServicesAuthorized.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-EnhancedCoverageRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEnhancedCoverageRestricted), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CE-ModeBRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBRestricted), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(277):
		if v.rowAerialUEsubscriptionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-AerialUEsubscriptionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAerialUEsubscriptionInformation), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-PendingDataIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPendingDataIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(41):
		if v.rowHandoverRestrictionList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-HandoverRestrictionList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s42.BridgeHandoverRestrictionListMethodMarshalAPERBudget(v.rowHandoverRestrictionList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-AdditionalRRMPriorityIndex:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.AdditionalRRMPriorityIndex, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.AdditionalRRMPriorityIndex
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 32, 32, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowAdditionalRRMPriorityIndex, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(306):
		if v.rowNRV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s24.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(341):
		if v.rowERABToBeUpdatedList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeUpdatedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s41.ERABToBeUpdatedListComplete{Value: *v.rowERABToBeUpdatedList}
		candidate, err := s41.BridgeERABToBeUpdatedListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-TimeRefDistribution:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeRefDistribution), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PathSwitchRequestAcknowledgeIEValue:", v.id)
	}
}

type UEContextModificationRequestIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowMMEUES1APID                         *s00.MMEUES1APID
	rowENBUES1APID                         *s00.ENBUES1APID
	rowSecurityKey                         *s00.SecurityKey
	rowSubscriberProfileIDforRFP           *s00.SubscriberProfileIDforRFP
	rowUEaggregateMaximumBitrate           *s35.UEAggregateMaximumBitrate
	rowCSFallbackIndicator                 *s00.CSFallbackIndicator
	rowUESecurityCapabilities              *s37.UESecurityCapabilities
	rowCSGMembershipStatus                 *s00.CSGMembershipStatus
	rowRegisteredLAI                       *s18.LAI
	rowAdditionalCSFallbackIndicator       *s00.AdditionalCSFallbackIndicator
	rowProSeAuthorized                     *s20.ProSeAuthorized
	rowSRVCCOperationPossible              *s00.SRVCCOperationPossible
	rowSRVCCOperationNotPossible           *s00.SRVCCOperationNotPossible
	rowV2XServicesAuthorized               *V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate   *s37.UESidelinkAggregateMaximumBitrate
	rowNRUESecurityCapabilities            *s19.NRUESecurityCapabilities
	rowAerialUEsubscriptionInformation     *s00.AerialUEsubscriptionInformation
	rowAdditionalRRMPriorityIndex          *s00.AdditionalRRMPriorityIndex
	rowIABAuthorized                       *s00.IABAuthorized
	rowNRV2XServicesAuthorized             *s19.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate *s19.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                    *s24.PC5QoSParameters
	rowUERadioCapabilityID                 *s00.UERadioCapabilityID
	rowTimeRefDistribution                 *s00.TimeRefDistribution
}

func (v UEContextModificationRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(73):
		return v.rowSecurityKey != nil
	case s00.ProtocolIEID(106):
		return v.rowSubscriberProfileIDforRFP != nil
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(108):
		return v.rowCSFallbackIndicator != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(159):
		return v.rowRegisteredLAI != nil
	case s00.ProtocolIEID(187):
		return v.rowAdditionalCSFallbackIndicator != nil
	case s00.ProtocolIEID(195):
		return v.rowProSeAuthorized != nil
	case s00.ProtocolIEID(124):
		return v.rowSRVCCOperationPossible != nil
	case s00.ProtocolIEID(243):
		return v.rowSRVCCOperationNotPossible != nil
	case s00.ProtocolIEID(240):
		return v.rowV2XServicesAuthorized != nil
	case s00.ProtocolIEID(248):
		return v.rowUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(277):
		return v.rowAerialUEsubscriptionInformation != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(301):
		return v.rowIABAuthorized != nil
	case s00.ProtocolIEID(306):
		return v.rowNRV2XServicesAuthorized != nil
	case s00.ProtocolIEID(307):
		return v.rowNRUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(308):
		return v.rowPC5QoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextModificationRequestIEValue and reports whether the opaque alternative is selected.
func (v *UEContextModificationRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs"}}
}
func (UEContextModificationRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(73):
		return aper.UnknownSelector
	case s00.ProtocolIEID(106):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(108):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(159):
		return aper.UnknownSelector
	case s00.ProtocolIEID(187):
		return aper.UnknownSelector
	case s00.ProtocolIEID(195):
		return aper.UnknownSelector
	case s00.ProtocolIEID(124):
		return aper.UnknownSelector
	case s00.ProtocolIEID(243):
		return aper.UnknownSelector
	case s00.ProtocolIEID(240):
		return aper.UnknownSelector
	case s00.ProtocolIEID(248):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(277):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(301):
		return aper.UnknownSelector
	case s00.ProtocolIEID(306):
		return aper.UnknownSelector
	case s00.ProtocolIEID(307):
		return aper.UnknownSelector
	case s00.ProtocolIEID(308):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(355):
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
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
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
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsSecurityKey returns the selected SecurityKey value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSecurityKey() (*s00.SecurityKey, bool) {
	if v == nil || v.id != s00.ProtocolIEID(73) || v.rowSecurityKey == nil {
		return nil, false
	}
	return v.rowSecurityKey, true
}

// AsSubscriberProfileIDforRFP returns the selected SubscriberProfileIDforRFP value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSubscriberProfileIDforRFP() (*s00.SubscriberProfileIDforRFP, bool) {
	if v == nil || v.id != s00.ProtocolIEID(106) || v.rowSubscriberProfileIDforRFP == nil {
		return nil, false
	}
	return v.rowSubscriberProfileIDforRFP, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUEaggregateMaximumBitrate() (*s35.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsCSFallbackIndicator returns the selected CSFallbackIndicator value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsCSFallbackIndicator() (*s00.CSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(108) || v.rowCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowCSFallbackIndicator, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsRegisteredLAI returns the selected RegisteredLAI value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsRegisteredLAI() (*s18.LAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(159) || v.rowRegisteredLAI == nil {
		return nil, false
	}
	return v.rowRegisteredLAI, true
}

// AsAdditionalCSFallbackIndicator returns the selected AdditionalCSFallbackIndicator value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAdditionalCSFallbackIndicator() (*s00.AdditionalCSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(187) || v.rowAdditionalCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowAdditionalCSFallbackIndicator, true
}

// AsProSeAuthorized returns the selected ProSeAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsProSeAuthorized() (*s20.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}

// AsSRVCCOperationPossible returns the selected SRVCCOperationPossible value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSRVCCOperationPossible() (*s00.SRVCCOperationPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(124) || v.rowSRVCCOperationPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationPossible, true
}

// AsSRVCCOperationNotPossible returns the selected SRVCCOperationNotPossible value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSRVCCOperationNotPossible() (*s00.SRVCCOperationNotPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(243) || v.rowSRVCCOperationNotPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationNotPossible, true
}

// AsV2XServicesAuthorized returns the selected V2XServicesAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsV2XServicesAuthorized() (*V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}

// AsUESidelinkAggregateMaximumBitrate returns the selected UESidelinkAggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUESidelinkAggregateMaximumBitrate() (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsAerialUEsubscriptionInformation returns the selected AerialUEsubscriptionInformation value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsIABAuthorized returns the selected IABAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsIABAuthorized() (*s00.IABAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(301) || v.rowIABAuthorized == nil {
		return nil, false
	}
	return v.rowIABAuthorized, true
}

// AsNRV2XServicesAuthorized returns the selected NRV2XServicesAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRV2XServicesAuthorized() (*s19.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}

// AsNRUESidelinkAggregateMaximumBitrate returns the selected NRUESidelinkAggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}

// AsPC5QoSParameters returns the selected PC5QoSParameters value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsPC5QoSParameters() (*s24.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsTimeRefDistribution returns the selected TimeRefDistribution value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v UEContextModificationRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationRequestIEValue, error) {
	out := UEContextModificationRequestIEValue{id: id}
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
	case s00.ProtocolIEID(73):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SecurityKey, error) {
			var v struct{ Value s00.SecurityKey }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 256, 256, true)
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
		out.rowSecurityKey = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(106):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false)
		value := s00.SubscriberProfileIDforRFP(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SubscriberProfileIDforRFP:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSubscriberProfileIDforRFP = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.UEAggregateMaximumBitrate
		child := scope
		if err := s35.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s35.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s35.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s35.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(108):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "CSFallbackIndicator"})
		value := s00.CSFallbackIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSFallbackIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSFallbackIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESecurityCapabilities
		child := scope
		if err := s37.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s37.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s37.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(146):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
		value := s00.CSGMembershipStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSGMembershipStatus = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(159):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.LAI
		child := scope
		if err := s18.BridgeLAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RegisteredLAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LAI")
		if err != nil {
			return out, err
		}
		*s18.BridgeLAIFieldPerPadding(&value) = padding
		*s18.BridgeLAIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeLAIFieldReceivedBytes(&value))
		*s18.BridgeLAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRegisteredLAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(187):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AdditionalCSFallbackIndicator"})
		value := s00.AdditionalCSFallbackIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AdditionalCSFallbackIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAdditionalCSFallbackIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.ProSeAuthorized
		child := scope
		if err := s20.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s20.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s20.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s20.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowProSeAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(124):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCOperationPossible"})
		value := s00.SRVCCOperationPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCOperationPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCOperationPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(243):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCOperationNotPossible"})
		value := s00.SRVCCOperationNotPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCOperationNotPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCOperationNotPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(240):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value V2XServicesAuthorized
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s37.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(269):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESecurityCapabilities
		child := scope
		if err := s19.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s19.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s19.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(277):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AerialUEsubscriptionInformation"})
		value := s00.AerialUEsubscriptionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AerialUEsubscriptionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAerialUEsubscriptionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(299):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.AdditionalRRMPriorityIndex, error) {
			var v struct {
				Value s00.AdditionalRRMPriorityIndex
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
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
		out.rowAdditionalRRMPriorityIndex = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(301):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IABAuthorized"})
		value := s00.IABAuthorized(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IABAuthorized:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIABAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(306):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRV2XServicesAuthorized
		child := scope
		if err := s19.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s19.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s19.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s24.PC5QoSParameters
		child := scope
		if err := s24.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s24.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s24.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s24.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s24.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPC5QoSParameters = &value
		raw.RetainContents(&out.received)
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
	case s00.ProtocolIEID(355):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeRefDistribution"})
		value := s00.TimeRefDistribution(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeRefDistribution:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeRefDistribution = &value
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
func (v UEContextModificationRequestIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(73):
		if v.rowSecurityKey == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SecurityKey:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SecurityKey, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SecurityKey }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 256, 256, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSecurityKey, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(106):
		if v.rowSubscriberProfileIDforRFP == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SubscriberProfileIDforRFP:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowSubscriberProfileIDforRFP), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(108):
		if v.rowCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-CSFallbackIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSFallbackIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-CSGMembershipStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSGMembershipStatus), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(159):
		if v.rowRegisteredLAI == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-RegisteredLAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeLAIMethodMarshalAPERBudget(v.rowRegisteredLAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(187):
		if v.rowAdditionalCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AdditionalCSFallbackIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAdditionalCSFallbackIndicator), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(124):
		if v.rowSRVCCOperationPossible == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SRVCCOperationPossible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCOperationPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(243):
		if v.rowSRVCCOperationNotPossible == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SRVCCOperationNotPossible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCOperationNotPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(240):
		if v.rowV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowV2XServicesAuthorized.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(277):
		if v.rowAerialUEsubscriptionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AerialUEsubscriptionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAerialUEsubscriptionInformation), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AdditionalRRMPriorityIndex:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.AdditionalRRMPriorityIndex, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.AdditionalRRMPriorityIndex
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 32, 32, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowAdditionalRRMPriorityIndex, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(301):
		if v.rowIABAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-IAB-Authorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIABAuthorized), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(306):
		if v.rowNRV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s24.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-TimeRefDistribution:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeRefDistribution), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationRequestIEValue:", v.id)
	}
}

type PathSwitchRequestAcknowledgeIETable struct{}

func PathSwitchRequestAcknowledgeIEs() PathSwitchRequestAcknowledgeIETable {
	return PathSwitchRequestAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) Table() s00.PathSwitchRequestAcknowledgeIEValueIETable {
	return func() s00.PathSwitchRequestAcknowledgeIEValueIETable {
		sealed := s00.PathSwitchRequestAcknowledgeIEValueIETable{}
		*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID() PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ENBUES1APID() PathSwitchRequestAcknowledgeENBUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEaggregateMaximumBitrate() PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s35.UEAggregateMaximumBitrateValueCodec {
		sealed := s35.UEAggregateMaximumBitrateValueCodec{}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s35.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s35.UEAggregateMaximumBitrate, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s35.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeSwitchedULList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(95), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeSwitchedULList"}}}
}

// ERABToBeSwitchedULList returns the typed binding for the ERABToBeSwitchedULList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeSwitchedULList() PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding {
	return PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding{info: t.infoERABToBeSwitchedULList(), codec: func() s17.ERABToBeSwitchedULListValueCodec {
		sealed := s17.ERABToBeSwitchedULListValueCodec{}
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULList"
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ERABToBeSwitchedULList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.ERABToBeSwitchedULList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSwitchedULList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(95), raw)
			if err != nil {
				var empty s17.ERABToBeSwitchedULList
				return empty, err
			}
			value, ok := decoded.AsERABToBeSwitchedULList()
			if !ok {
				var empty s17.ERABToBeSwitchedULList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeSwitchedULList: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldEncode(&sealed) = func(value s17.ERABToBeSwitchedULList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(95), rowERABToBeSwitchedULList: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldCapture(&sealed) = func(v s17.ERABToBeSwitchedULList, options aper.DecodeState) (s17.ERABToBeSwitchedULList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APERABToBeSwitchedULList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldCompare(&sealed) = func(v s17.ERABToBeSwitchedULList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APERABToBeSwitchedULList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeERABToBeSwitchedULListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedULList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.ERABToBeSwitchedULList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(95), rowERABToBeSwitchedULList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s17.ERABToBeSwitchedULList, bool) {
			return value.AsERABToBeSwitchedULList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(33), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeReleasedList"}}}
}

// ERABToBeReleasedList returns the typed binding for the ERABToBeReleasedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeReleasedList() PathSwitchRequestAcknowledgeERABListIEBinding {
	return PathSwitchRequestAcknowledgeERABListIEBinding{info: t.infoERABToBeReleasedList(), codec: func() s16.ERABListValueCodec {
		sealed := s16.ERABListValueCodec{}
		*s16.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s16.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(33), raw)
			if err != nil {
				var empty s16.ERABList
				return empty, err
			}
			value, ok := decoded.AsERABToBeReleasedList()
			if !ok {
				var empty s16.ERABList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeReleasedList: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s16.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s16.ERABList, options aper.DecodeState) (s16.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s16.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.ERABList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s16.ERABList, bool) {
			return value.AsERABToBeReleasedList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-SecurityContext"}}}
}

// SecurityContext returns the typed binding for the SecurityContext row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SecurityContext() PathSwitchRequestAcknowledgeSecurityContextIEBinding {
	return PathSwitchRequestAcknowledgeSecurityContextIEBinding{info: t.infoSecurityContext(), codec: func() s28.SecurityContextValueCodec {
		sealed := s28.SecurityContextValueCodec{}
		*s28.BridgeSecurityContextValueCodecFieldPath(&sealed) = "SecurityContext"
		*s28.BridgeSecurityContextValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecurityContext, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecurityContext
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityContext")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(40), raw)
			if err != nil {
				var empty s28.SecurityContext
				return empty, err
			}
			value, ok := decoded.AsSecurityContext()
			if !ok {
				var empty s28.SecurityContext
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-SecurityContext: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecurityContextValueCodecFieldEncode(&sealed) = func(value s28.SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecurityContextValueCodecFieldCapture(&sealed) = func(v s28.SecurityContext, options aper.DecodeState) (s28.SecurityContext, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecurityContext(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecurityContextValueCodecFieldCompare(&sealed) = func(v s28.SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecurityContext(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s28.BridgeSecurityContextValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecurityContext) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s28.SecurityContext, bool) {
			return value.AsSecurityContext()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CriticalityDiagnostics() PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding {
	return PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID2() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(158), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID-2"}}}
}

// MMEUES1APID2 returns the typed binding for the MMEUES1APID2 row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID2() PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID2(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(158), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID2()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID-2: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID2()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CSGMembershipStatus() PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding {
	return PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSGMembershipStatus) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ProSeAuthorized() PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding{info: t.infoProSeAuthorized(), codec: func() s20.ProSeAuthorizedValueCodec {
		sealed := s20.ProSeAuthorizedValueCodec{}
		*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
		*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(195), raw)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, err
			}
			value, ok := decoded.AsProSeAuthorized()
			if !ok {
				var empty s20.ProSeAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-ProSeAuthorized: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APProSeAuthorized(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.ProSeAuthorized) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUEUserPlaneCIoTSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(241), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEUserPlaneCIoTSupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UEUserPlaneCIoTSupportIndicator"}}}
}

// UEUserPlaneCIoTSupportIndicator returns the typed binding for the UEUserPlaneCIoTSupportIndicator row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEUserPlaneCIoTSupportIndicator() PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding {
	return PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding{info: t.infoUEUserPlaneCIoTSupportIndicator(), codec: func() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
		sealed := s02.UEUserPlaneCIoTSupportIndicatorValueCodec{}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(&sealed) = "UEUserPlaneCIoTSupportIndicator"
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEUserPlaneCIoTSupportIndicator")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(241), raw)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, err
			}
			value, ok := decoded.AsUEUserPlaneCIoTSupportIndicator()
			if !ok {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UEUserPlaneCIoTSupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUserPlaneCIoTSupportIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEUserPlaneCIoTSupportIndicator) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
			return value.AsUEUserPlaneCIoTSupportIndicator()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) V2XServicesAuthorized() PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: V2XServicesAuthorizedValueCodec{path: "V2XServicesAuthorized",
		decode: func(data []byte, options aper.DecodeState) (V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty V2XServicesAuthorized
				return empty, err
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty V2XServicesAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		},
		encode: func(value V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}, capture: func(v V2XServicesAuthorized, options aper.DecodeState) (V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}, compare: func(v V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value V2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
		return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}
	}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*V2XServicesAuthorized, bool) {
		return value.AsV2XServicesAuthorized()
	}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESidelinkAggregateMaximumBitrate() PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoUESidelinkAggregateMaximumBitrate(), codec: func() s37.UESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s37.UESidelinkAggregateMaximumBitrateValueCodec{}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(248), raw)
			if err != nil {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) EnhancedCoverageRestricted() PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding {
	return PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCapture(&sealed) = func(v s00.EnhancedCoverageRestricted, options aper.DecodeState) (s00.EnhancedCoverageRestricted, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEnhancedCoverageRestricted(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCompare(&sealed) = func(v s00.EnhancedCoverageRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEnhancedCoverageRestricted(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnhancedCoverageRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EnhancedCoverageRestricted) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESecurityCapabilities() PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s19.NRUESecurityCapabilitiesValueCodec {
		sealed := s19.NRUESecurityCapabilitiesValueCodec{}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s19.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s19.NRUESecurityCapabilities, options aper.DecodeState) (s19.NRUESecurityCapabilities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s19.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRUESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CEModeBRestricted() PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding {
	return PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCapture(&sealed) = func(v s00.CEModeBRestricted, options aper.DecodeState) (s00.CEModeBRestricted, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBRestricted(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCompare(&sealed) = func(v s00.CEModeBRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBRestricted(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBRestricted) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AerialUEsubscriptionInformation() PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding {
	return PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding{info: t.infoAerialUEsubscriptionInformation(), codec: func() s00.AerialUEsubscriptionInformationValueCodec {
		sealed := s00.AerialUEsubscriptionInformationValueCodec{}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(277), raw)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			value, ok := decoded.AsAerialUEsubscriptionInformation()
			if !ok {
				var empty s00.AerialUEsubscriptionInformation
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AerialUEsubscriptionInformation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AerialUEsubscriptionInformation) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PendingDataIndication() PathSwitchRequestAcknowledgePendingDataIndicationIEBinding {
	return PathSwitchRequestAcknowledgePendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PendingDataIndication")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePendingDataIndicationValueCodecFieldCapture(&sealed) = func(v s00.PendingDataIndication, options aper.DecodeState) (s00.PendingDataIndication, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPendingDataIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgePendingDataIndicationValueCodecFieldCompare(&sealed) = func(v s00.PendingDataIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPendingDataIndication(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePendingDataIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PendingDataIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PendingDataIndication) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SubscriptionBasedUEDifferentiationInfo() PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding {
	return PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: func() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
		sealed := s31.SubscriptionBasedUEDifferentiationInfoValueCodec{}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s30.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.SubscriptionBasedUEDifferentiationInfo) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-HandoverRestrictionList"}}}
}

// HandoverRestrictionList returns the typed binding for the HandoverRestrictionList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) HandoverRestrictionList() PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding {
	return PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding{info: t.infoHandoverRestrictionList(), codec: func() s42.HandoverRestrictionListValueCodec {
		sealed := s42.HandoverRestrictionListValueCodec{}
		*s42.BridgeHandoverRestrictionListValueCodecFieldPath(&sealed) = "HandoverRestrictionList"
		*s42.BridgeHandoverRestrictionListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.HandoverRestrictionList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s42.HandoverRestrictionList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("HandoverRestrictionList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(41), raw)
			if err != nil {
				var empty s42.HandoverRestrictionList
				return empty, err
			}
			value, ok := decoded.AsHandoverRestrictionList()
			if !ok {
				var empty s42.HandoverRestrictionList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-HandoverRestrictionList: no selected value")
			}
			return *value, nil
		}
		*s42.BridgeHandoverRestrictionListValueCodecFieldEncode(&sealed) = func(value s42.HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}).encodeFresh(fresh, budget)
		}
		*s42.BridgeHandoverRestrictionListValueCodecFieldCapture(&sealed) = func(v s42.HandoverRestrictionList, options aper.DecodeState) (s42.HandoverRestrictionList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s42.BridgeCaptureS1APHandoverRestrictionList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s42.BridgeHandoverRestrictionListValueCodecFieldCompare(&sealed) = func(v s42.HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s42.BridgeCompareS1APHandoverRestrictionList(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeHandoverRestrictionListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s42.HandoverRestrictionList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s42.HandoverRestrictionList, bool) {
			return value.AsHandoverRestrictionList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AdditionalRRMPriorityIndex() PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding {
	return PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AdditionalRRMPriorityIndex) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRV2XServicesAuthorized() PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding{info: t.infoNRV2XServicesAuthorized(), codec: func() s19.NRV2XServicesAuthorizedValueCodec {
		sealed := s19.NRV2XServicesAuthorizedValueCodec{}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRV2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRV2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(306), raw)
			if err != nil {
				var empty s19.NRV2XServicesAuthorized
				return empty, err
			}
			value, ok := decoded.AsNRV2XServicesAuthorized()
			if !ok {
				var empty s19.NRV2XServicesAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRV2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s19.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s19.NRV2XServicesAuthorized, options aper.DecodeState) (s19.NRV2XServicesAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s19.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRV2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s19.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESidelinkAggregateMaximumBitrate() PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoNRUESidelinkAggregateMaximumBitrate(), codec: func() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s19.NRUESidelinkAggregateMaximumBitrateValueCodec{}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(307), raw)
			if err != nil {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRUESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PC5QoSParameters() PathSwitchRequestAcknowledgePC5QoSParametersIEBinding {
	return PathSwitchRequestAcknowledgePC5QoSParametersIEBinding{info: t.infoPC5QoSParameters(), codec: func() s24.PC5QoSParametersValueCodec {
		sealed := s24.PC5QoSParametersValueCodec{}
		*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
		*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(308), raw)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, err
			}
			value, ok := decoded.AsPC5QoSParameters()
			if !ok {
				var empty s24.PC5QoSParameters
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PC5QoSParameters: no selected value")
			}
			return *value, nil
		}
		*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s24.PC5QoSParameters) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UERadioCapabilityID() PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding {
	return PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
			s07.BridgeCompareS1APUERadioCapabilityID(&v, &s)
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
		inject: func(value s00.UERadioCapabilityID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESecurityCapabilities() PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s37.UESecurityCapabilitiesValueCodec {
		sealed := s37.UESecurityCapabilitiesValueCodec{}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s37.UESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s37.UESecurityCapabilities, options aper.DecodeState) (s37.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s37.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeUpdatedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(341), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeUpdatedList"}}}
}

// ERABToBeUpdatedList returns the typed binding for the ERABToBeUpdatedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeUpdatedList() PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding {
	return PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding{info: t.infoERABToBeUpdatedList(), codec: func() s29.ERABToBeUpdatedListValueCodec {
		sealed := s29.ERABToBeUpdatedListValueCodec{}
		*s29.BridgeERABToBeUpdatedListValueCodecFieldPath(&sealed) = "ERABToBeUpdatedList"
		*s29.BridgeERABToBeUpdatedListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.ERABToBeUpdatedList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s29.ERABToBeUpdatedList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeUpdatedList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(341), raw)
			if err != nil {
				var empty s29.ERABToBeUpdatedList
				return empty, err
			}
			value, ok := decoded.AsERABToBeUpdatedList()
			if !ok {
				var empty s29.ERABToBeUpdatedList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeUpdatedList: no selected value")
			}
			return *value, nil
		}
		*s29.BridgeERABToBeUpdatedListValueCodecFieldEncode(&sealed) = func(value s29.ERABToBeUpdatedList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(341), rowERABToBeUpdatedList: &value}).encodeFresh(fresh, budget)
		}
		*s29.BridgeERABToBeUpdatedListValueCodecFieldCapture(&sealed) = func(v s29.ERABToBeUpdatedList, options aper.DecodeState) (s29.ERABToBeUpdatedList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APERABToBeUpdatedList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeERABToBeUpdatedListValueCodecFieldCompare(&sealed) = func(v s29.ERABToBeUpdatedList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APERABToBeUpdatedList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeERABToBeUpdatedListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeUpdatedList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s29.ERABToBeUpdatedList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(341), rowERABToBeUpdatedList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s29.ERABToBeUpdatedList, bool) {
			return value.AsERABToBeUpdatedList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) TimeRefDistribution() PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding {
	return PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding{info: t.infoTimeRefDistribution(), codec: func() s02.TimeRefDistributionValueCodec {
		sealed := s02.TimeRefDistributionValueCodec{}
		*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
		*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(355), raw)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			value, ok := decoded.AsTimeRefDistribution()
			if !ok {
				var empty s00.TimeRefDistribution
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-TimeRefDistribution: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeRefDistribution) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PathSwitchRequestAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(95):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedULList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(33):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(158):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID-2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(241):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEUserPlaneCIoTSupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(341):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeUpdatedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return PathSwitchRequestAcknowledgeIEField{Id: id, Criticality: criticality, Value: PathSwitchRequestAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationRequestIETable struct{}

func UEContextModificationRequestIEs() UEContextModificationRequestIETable {
	return UEContextModificationRequestIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) Table() s00.UEContextModificationRequestIEValueIETable {
	return func() s00.UEContextModificationRequestIEValueIETable {
		sealed := s00.UEContextModificationRequestIEValueIETable{}
		*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) MMEUES1APID() UEContextModificationRequestMMEUES1APIDIEBinding {
	return UEContextModificationRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ENBUES1APID() UEContextModificationRequestENBUES1APIDIEBinding {
	return UEContextModificationRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationRequestIETable) infoSecurityKey() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(73), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityKey"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SecurityKey"}}}
}

// SecurityKey returns the typed binding for the SecurityKey row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SecurityKey() UEContextModificationRequestSecurityKeyIEBinding {
	return UEContextModificationRequestSecurityKeyIEBinding{info: t.infoSecurityKey(), codec: func() s01.SecurityKeyValueCodec {
		sealed := s01.SecurityKeyValueCodec{}
		*s01.BridgeSecurityKeyValueCodecFieldPath(&sealed) = "SecurityKey"
		*s01.BridgeSecurityKeyValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecurityKey, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SecurityKey
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityKey")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(73), raw)
			if err != nil {
				var empty s00.SecurityKey
				return empty, err
			}
			value, ok := decoded.AsSecurityKey()
			if !ok {
				var empty s00.SecurityKey
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SecurityKey: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSecurityKeyValueCodecFieldEncode(&sealed) = func(value s00.SecurityKey, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSecurityKeyValueCodecFieldCapture(&sealed) = func(v s00.SecurityKey, options aper.DecodeState) (s00.SecurityKey, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSecurityKey(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSecurityKeyValueCodecFieldCompare(&sealed) = func(v s00.SecurityKey, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APSecurityKey(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeSecurityKeyValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityKey"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SecurityKey) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SecurityKey, bool) {
			return value.AsSecurityKey()
		}}
}
func (UEContextModificationRequestIETable) infoSubscriberProfileIDforRFP() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(106), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SubscriberProfileIDforRFP"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SubscriberProfileIDforRFP"}}}
}

// SubscriberProfileIDforRFP returns the typed binding for the SubscriberProfileIDforRFP row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SubscriberProfileIDforRFP() UEContextModificationRequestSubscriberProfileIDforRFPIEBinding {
	return UEContextModificationRequestSubscriberProfileIDforRFPIEBinding{info: t.infoSubscriberProfileIDforRFP(), codec: func() s01.SubscriberProfileIDforRFPValueCodec {
		sealed := s01.SubscriberProfileIDforRFPValueCodec{}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldPath(&sealed) = "SubscriberProfileIDforRFP"
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriberProfileIDforRFP")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(106), raw)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			value, ok := decoded.AsSubscriberProfileIDforRFP()
			if !ok {
				var empty s00.SubscriberProfileIDforRFP
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SubscriberProfileIDforRFP: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&sealed) = func(value s00.SubscriberProfileIDforRFP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCapture(&sealed) = func(v s00.SubscriberProfileIDforRFP, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSubscriberProfileIDforRFP(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCompare(&sealed) = func(v s00.SubscriberProfileIDforRFP, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APSubscriberProfileIDforRFP(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriberProfileIDforRFP"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SubscriberProfileIDforRFP) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
			return value.AsSubscriberProfileIDforRFP()
		}}
}
func (UEContextModificationRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UEaggregateMaximumBitrate() UEContextModificationRequestUEAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s35.UEAggregateMaximumBitrateValueCodec {
		sealed := s35.UEAggregateMaximumBitrateValueCodec{}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s35.UEAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s35.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s35.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s35.UEAggregateMaximumBitrate, options aper.DecodeState) (s35.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s35.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s35.UEAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(108), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSFallbackIndicator"}}}
}

// CSFallbackIndicator returns the typed binding for the CSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSFallbackIndicator() UEContextModificationRequestCSFallbackIndicatorIEBinding {
	return UEContextModificationRequestCSFallbackIndicatorIEBinding{info: t.infoCSFallbackIndicator(), codec: func() s00.CSFallbackIndicatorValueCodec {
		sealed := s00.CSFallbackIndicatorValueCodec{}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldPath(&sealed) = "CSFallbackIndicator"
		*s00.BridgeCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSFallbackIndicator")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(108), raw)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, err
			}
			value, ok := decoded.AsCSFallbackIndicator()
			if !ok {
				var empty s00.CSFallbackIndicator
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.CSFallbackIndicator, options aper.DecodeState) (s00.CSFallbackIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSFallbackIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.CSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSFallbackIndicator(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSFallbackIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSFallbackIndicator) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.CSFallbackIndicator, bool) {
			return value.AsCSFallbackIndicator()
		}}
}
func (UEContextModificationRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESecurityCapabilities() UEContextModificationRequestUESecurityCapabilitiesIEBinding {
	return UEContextModificationRequestUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s37.UESecurityCapabilitiesValueCodec {
		sealed := s37.UESecurityCapabilitiesValueCodec{}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s37.UESecurityCapabilities
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s37.UESecurityCapabilities, options aper.DecodeState) (s37.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s37.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESecurityCapabilities) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (UEContextModificationRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSGMembershipStatus() UEContextModificationRequestCSGMembershipStatusIEBinding {
	return UEContextModificationRequestCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSGMembershipStatus) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (UEContextModificationRequestIETable) infoRegisteredLAI() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(159), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-RegisteredLAI"}}}
}

// RegisteredLAI returns the typed binding for the RegisteredLAI row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) RegisteredLAI() UEContextModificationRequestLAIIEBinding {
	return UEContextModificationRequestLAIIEBinding{info: t.infoRegisteredLAI(), codec: func() s18.LAIValueCodec {
		sealed := s18.LAIValueCodec{}
		*s18.BridgeLAIValueCodecFieldPath(&sealed) = "LAI"
		*s18.BridgeLAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LAI")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(159), raw)
			if err != nil {
				var empty s18.LAI
				return empty, err
			}
			value, ok := decoded.AsRegisteredLAI()
			if !ok {
				var empty s18.LAI
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-RegisteredLAI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLAIValueCodecFieldEncode(&sealed) = func(value s18.LAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeLAIValueCodecFieldCapture(&sealed) = func(v s18.LAI, options aper.DecodeState) (s18.LAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APLAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s18.BridgeLAIValueCodecFieldCompare(&sealed) = func(v s18.LAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APLAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeLAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.LAI) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s18.LAI, bool) { return value.AsRegisteredLAI() }}
}
func (UEContextModificationRequestIETable) infoAdditionalCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(187), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalCSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalCSFallbackIndicator"}}}
}

// AdditionalCSFallbackIndicator returns the typed binding for the AdditionalCSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalCSFallbackIndicator() UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding {
	return UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding{info: t.infoAdditionalCSFallbackIndicator(), codec: func() s00.AdditionalCSFallbackIndicatorValueCodec {
		sealed := s00.AdditionalCSFallbackIndicatorValueCodec{}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldPath(&sealed) = "AdditionalCSFallbackIndicator"
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalCSFallbackIndicator")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(187), raw)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, err
			}
			value, ok := decoded.AsAdditionalCSFallbackIndicator()
			if !ok {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalCSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.AdditionalCSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.AdditionalCSFallbackIndicator, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAdditionalCSFallbackIndicator(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.AdditionalCSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s02.BridgeCompareS1APAdditionalCSFallbackIndicator(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalCSFallbackIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AdditionalCSFallbackIndicator) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
			return value.AsAdditionalCSFallbackIndicator()
		}}
}
func (UEContextModificationRequestIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ProSeAuthorized() UEContextModificationRequestProSeAuthorizedIEBinding {
	return UEContextModificationRequestProSeAuthorizedIEBinding{info: t.infoProSeAuthorized(), codec: func() s20.ProSeAuthorizedValueCodec {
		sealed := s20.ProSeAuthorizedValueCodec{}
		*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
		*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(195), raw)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, err
			}
			value, ok := decoded.AsProSeAuthorized()
			if !ok {
				var empty s20.ProSeAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-ProSeAuthorized: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APProSeAuthorized(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.ProSeAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationPossible"}}}
}

// SRVCCOperationPossible returns the typed binding for the SRVCCOperationPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationPossible() UEContextModificationRequestSRVCCOperationPossibleIEBinding {
	return UEContextModificationRequestSRVCCOperationPossibleIEBinding{info: t.infoSRVCCOperationPossible(), codec: func() s01.SRVCCOperationPossibleValueCodec {
		sealed := s01.SRVCCOperationPossibleValueCodec{}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCOperationPossible")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(124), raw)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			value, ok := decoded.AsSRVCCOperationPossible()
			if !ok {
				var empty s00.SRVCCOperationPossible
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationPossible: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationPossible, options aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCOperationPossible(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APSRVCCOperationPossible(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCOperationPossible) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}}
}
func (UEContextModificationRequestIETable) infoSRVCCOperationNotPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(243), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationNotPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationNotPossible"}}}
}

// SRVCCOperationNotPossible returns the typed binding for the SRVCCOperationNotPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationNotPossible() UEContextModificationRequestSRVCCOperationNotPossibleIEBinding {
	return UEContextModificationRequestSRVCCOperationNotPossibleIEBinding{info: t.infoSRVCCOperationNotPossible(), codec: func() s01.SRVCCOperationNotPossibleValueCodec {
		sealed := s01.SRVCCOperationNotPossibleValueCodec{}
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationNotPossible"
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationNotPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationNotPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCOperationNotPossible")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(243), raw)
			if err != nil {
				var empty s00.SRVCCOperationNotPossible
				return empty, err
			}
			value, ok := decoded.AsSRVCCOperationNotPossible()
			if !ok {
				var empty s00.SRVCCOperationNotPossible
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationNotPossible: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationNotPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(243), rowSRVCCOperationNotPossible: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationNotPossible, options aper.DecodeState) (s00.SRVCCOperationNotPossible, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCOperationNotPossible(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationNotPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APSRVCCOperationNotPossible(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSRVCCOperationNotPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationNotPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCOperationNotPossible) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(243), rowSRVCCOperationNotPossible: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SRVCCOperationNotPossible, bool) {
			return value.AsSRVCCOperationNotPossible()
		}}
}
func (UEContextModificationRequestIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) V2XServicesAuthorized() UEContextModificationRequestV2XServicesAuthorizedIEBinding {
	return UEContextModificationRequestV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: V2XServicesAuthorizedValueCodec{path: "V2XServicesAuthorized",
		decode: func(data []byte, options aper.DecodeState) (V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty V2XServicesAuthorized
				return empty, err
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty V2XServicesAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		},
		encode: func(value V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}, capture: func(v V2XServicesAuthorized, options aper.DecodeState) (V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}, compare: func(v V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value V2XServicesAuthorized) UEContextModificationRequestIEValue {
		return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}
	}, get: func(value *UEContextModificationRequestIEValue) (*V2XServicesAuthorized, bool) {
		return value.AsV2XServicesAuthorized()
	}}
}
func (UEContextModificationRequestIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESidelinkAggregateMaximumBitrate() UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoUESidelinkAggregateMaximumBitrate(), codec: func() s37.UESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s37.UESidelinkAggregateMaximumBitrateValueCodec{}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(248), raw)
			if err != nil {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s37.UESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s37.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s37.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s37.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESecurityCapabilities() UEContextModificationRequestNRUESecurityCapabilitiesIEBinding {
	return UEContextModificationRequestNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s19.NRUESecurityCapabilitiesValueCodec {
		sealed := s19.NRUESecurityCapabilitiesValueCodec{}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s19.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s19.NRUESecurityCapabilities, options aper.DecodeState) (s19.NRUESecurityCapabilities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s19.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRUESecurityCapabilities) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (UEContextModificationRequestIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AerialUEsubscriptionInformation() UEContextModificationRequestAerialUEsubscriptionInformationIEBinding {
	return UEContextModificationRequestAerialUEsubscriptionInformationIEBinding{info: t.infoAerialUEsubscriptionInformation(), codec: func() s00.AerialUEsubscriptionInformationValueCodec {
		sealed := s00.AerialUEsubscriptionInformationValueCodec{}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(277), raw)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			value, ok := decoded.AsAerialUEsubscriptionInformation()
			if !ok {
				var empty s00.AerialUEsubscriptionInformation
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AerialUEsubscriptionInformation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AerialUEsubscriptionInformation) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}}
}
func (UEContextModificationRequestIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalRRMPriorityIndex() UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding {
	return UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AdditionalRRMPriorityIndex) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (UEContextModificationRequestIETable) infoIABAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(301), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Authorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-IAB-Authorized"}}}
}

// IABAuthorized returns the typed binding for the IABAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) IABAuthorized() UEContextModificationRequestIABAuthorizedIEBinding {
	return UEContextModificationRequestIABAuthorizedIEBinding{info: t.infoIABAuthorized(), codec: func() s00.IABAuthorizedValueCodec {
		sealed := s00.IABAuthorizedValueCodec{}
		*s00.BridgeIABAuthorizedValueCodecFieldPath(&sealed) = "IABAuthorized"
		*s00.BridgeIABAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("IABAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(301), raw)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, err
			}
			value, ok := decoded.AsIABAuthorized()
			if !ok {
				var empty s00.IABAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-IAB-Authorized: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeIABAuthorizedValueCodecFieldEncode(&sealed) = func(value s00.IABAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeIABAuthorizedValueCodecFieldCapture(&sealed) = func(v s00.IABAuthorized, options aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIABAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeIABAuthorizedValueCodecFieldCompare(&sealed) = func(v s00.IABAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIABAuthorized(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeIABAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IABAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.IABAuthorized, bool) {
			return value.AsIABAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRV2XServicesAuthorized() UEContextModificationRequestNRV2XServicesAuthorizedIEBinding {
	return UEContextModificationRequestNRV2XServicesAuthorizedIEBinding{info: t.infoNRV2XServicesAuthorized(), codec: func() s19.NRV2XServicesAuthorizedValueCodec {
		sealed := s19.NRV2XServicesAuthorizedValueCodec{}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRV2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRV2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(306), raw)
			if err != nil {
				var empty s19.NRV2XServicesAuthorized
				return empty, err
			}
			value, ok := decoded.AsNRV2XServicesAuthorized()
			if !ok {
				var empty s19.NRV2XServicesAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRV2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s19.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s19.NRV2XServicesAuthorized, options aper.DecodeState) (s19.NRV2XServicesAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s19.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRV2XServicesAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s19.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESidelinkAggregateMaximumBitrate() UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoNRUESidelinkAggregateMaximumBitrate(), codec: func() s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s19.NRUESidelinkAggregateMaximumBitrateValueCodec{}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(307), raw)
			if err != nil {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s19.NRUESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s19.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s19.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s19.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRUESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) PC5QoSParameters() UEContextModificationRequestPC5QoSParametersIEBinding {
	return UEContextModificationRequestPC5QoSParametersIEBinding{info: t.infoPC5QoSParameters(), codec: func() s24.PC5QoSParametersValueCodec {
		sealed := s24.PC5QoSParametersValueCodec{}
		*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
		*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(308), raw)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, err
			}
			value, ok := decoded.AsPC5QoSParameters()
			if !ok {
				var empty s24.PC5QoSParameters
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-PC5QoSParameters: no selected value")
			}
			return *value, nil
		}
		*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s24.PC5QoSParameters) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}}
}
func (UEContextModificationRequestIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UERadioCapabilityID() UEContextModificationRequestUERadioCapabilityIDIEBinding {
	return UEContextModificationRequestUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
			s07.BridgeCompareS1APUERadioCapabilityID(&v, &s)
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
		inject: func(value s00.UERadioCapabilityID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (UEContextModificationRequestIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) TimeRefDistribution() UEContextModificationRequestTimeRefDistributionIEBinding {
	return UEContextModificationRequestTimeRefDistributionIEBinding{info: t.infoTimeRefDistribution(), codec: func() s02.TimeRefDistributionValueCodec {
		sealed := s02.TimeRefDistributionValueCodec{}
		*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
		*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(355), raw)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			value, ok := decoded.AsTimeRefDistribution()
			if !ok {
				var empty s00.TimeRefDistribution
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-TimeRefDistribution: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeRefDistribution) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(73):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityKey requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(106):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SubscriberProfileIDforRFP requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(108):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(159):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RegisteredLAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(187):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalCSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(243):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationNotPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(301):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Authorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationRequestIEField{Id: id, Criticality: criticality, Value: UEContextModificationRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ERABToBeSwitchedULListCodec binds the complete APER value type.
func ERABToBeSwitchedULListCodec() s17.ERABToBeSwitchedULListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Codec()
}

// ERABToBeUpdatedListCodec binds the complete APER value type.
func ERABToBeUpdatedListCodec() s29.ERABToBeUpdatedListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Codec()
}

// SRVCCOperationNotPossibleCodec binds the complete APER value type.
func SRVCCOperationNotPossibleCodec() s01.SRVCCOperationNotPossibleValueCodec {
	return UEContextModificationRequestIEs().SRVCCOperationNotPossible().Codec()
}
func BridgeERABReleaseResponseAPERValueFieldContext(v *ERABReleaseResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseAPERValueFieldReceived(v *ERABReleaseResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABReleaseResponseAPERValueFieldReplay(v *ERABReleaseResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABReleaseResponseAPERValueFieldWithoutReplay(v *ERABReleaseResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseFieldExtCount(v *ERABReleaseResponse) *int64   { return &v.extCount }
func BridgeERABReleaseResponseFieldExtData(v *ERABReleaseResponse) *[][]byte { return &v.extData }
func BridgeERABReleaseResponseFieldExtOrigin(v *ERABReleaseResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABReleaseResponseFieldExtPresent(v *ERABReleaseResponse) *[]bool { return &v.extPresent }
func BridgeERABReleaseResponseFieldExtWire(v *ERABReleaseResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeERABReleaseResponseFieldPerExtPadding(v *ERABReleaseResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABReleaseResponseFieldPerPadding(v *ERABReleaseResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABReleaseResponseFieldProtocolIEsIndef(v *ERABReleaseResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABReleaseResponseFieldReceived(v *ERABReleaseResponse) *bool { return &v.received }
func BridgeERABReleaseResponseFieldReceivedAbsolute(v *ERABReleaseResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeERABReleaseResponseFieldReceivedBytes(v *ERABReleaseResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABReleaseResponseFieldReceivedLocation(v *ERABReleaseResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABReleaseResponseFieldReplay(v *ERABReleaseResponse) *aper.Snapshot { return &v.replay }
func BridgeERABReleaseResponseFieldStream(v *ERABReleaseResponse) *aper.WireSpan { return &v.stream }
func BridgeERABReleaseResponseFieldWithoutReplay(v *ERABReleaseResponse) *bool {
	return &v.withoutReplay
}
func BridgeERABReleaseResponseMethodMarshalAPERBudget(v *ERABReleaseResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABReleaseResponseMethodMarshalAPERBudgetValue(v *ERABReleaseResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABReleaseResponseMethodMarshalAPERChanged(v *ERABReleaseResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABReleaseResponseMethodMarshalAPERChangedValue(v *ERABReleaseResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABReleaseResponseMethodMarshalAPERLegacy(v *ERABReleaseResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABReleaseResponseMethodMarshalAPERNewValue(v *ERABReleaseResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABReleaseResponseMethodMarshalAPERPlanned(v *ERABReleaseResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABReleaseResponseMethodMarshalAPERTo(v *ERABReleaseResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABReleaseResponseMethodUnmarshalAPERFrom(v *ERABReleaseResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABReleaseResponseMethodUnmarshalAPERLegacy(v *ERABReleaseResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABReleaseResponseMethodUnmarshalAPERWithOptions(v *ERABReleaseResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABReleaseResponseValueCodecFieldCapture(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, aper.DecodeState) (ERABReleaseResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseValueCodecFieldCompare(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseValueCodecFieldContext(v *ERABReleaseResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseValueCodecFieldDecode(v *ERABReleaseResponseValueCodec) *func([]byte, aper.DecodeState) (ERABReleaseResponse, error) {
	return &v.decode
}
func BridgeERABReleaseResponseValueCodecFieldEncode(v *ERABReleaseResponseValueCodec) *func(ERABReleaseResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseValueCodecFieldPath(v *ERABReleaseResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABReleaseResponseValueCodecMethodEncodeBudgetValue(v ERABReleaseResponseValueCodec, a0 ERABReleaseResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABReleaseResponseValueCodecMethodEncodeChanged(v ERABReleaseResponseValueCodec, a0 ERABReleaseResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABSetupResponseAPERValueFieldContext(v *ERABSetupResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseAPERValueFieldReceived(v *ERABSetupResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABSetupResponseAPERValueFieldReplay(v *ERABSetupResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABSetupResponseAPERValueFieldWithoutReplay(v *ERABSetupResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABSetupResponseFieldExtCount(v *ERABSetupResponse) *int64   { return &v.extCount }
func BridgeERABSetupResponseFieldExtData(v *ERABSetupResponse) *[][]byte { return &v.extData }
func BridgeERABSetupResponseFieldExtOrigin(v *ERABSetupResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeERABSetupResponseFieldExtPresent(v *ERABSetupResponse) *[]bool       { return &v.extPresent }
func BridgeERABSetupResponseFieldExtWire(v *ERABSetupResponse) *[]aper.WireSpan { return &v.extWire }
func BridgeERABSetupResponseFieldPerExtPadding(v *ERABSetupResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeERABSetupResponseFieldPerPadding(v *ERABSetupResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeERABSetupResponseFieldProtocolIEsIndef(v *ERABSetupResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeERABSetupResponseFieldReceived(v *ERABSetupResponse) *bool { return &v.received }
func BridgeERABSetupResponseFieldReceivedAbsolute(v *ERABSetupResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeERABSetupResponseFieldReceivedBytes(v *ERABSetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeERABSetupResponseFieldReceivedLocation(v *ERABSetupResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeERABSetupResponseFieldReplay(v *ERABSetupResponse) *aper.Snapshot { return &v.replay }
func BridgeERABSetupResponseFieldStream(v *ERABSetupResponse) *aper.WireSpan { return &v.stream }
func BridgeERABSetupResponseFieldWithoutReplay(v *ERABSetupResponse) *bool   { return &v.withoutReplay }
func BridgeERABSetupResponseMethodMarshalAPERBudget(v *ERABSetupResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABSetupResponseMethodMarshalAPERBudgetValue(v *ERABSetupResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeERABSetupResponseMethodMarshalAPERChanged(v *ERABSetupResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeERABSetupResponseMethodMarshalAPERChangedValue(v *ERABSetupResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeERABSetupResponseMethodMarshalAPERLegacy(v *ERABSetupResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABSetupResponseMethodMarshalAPERNewValue(v *ERABSetupResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeERABSetupResponseMethodMarshalAPERPlanned(v *ERABSetupResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeERABSetupResponseMethodMarshalAPERTo(v *ERABSetupResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABSetupResponseMethodUnmarshalAPERFrom(v *ERABSetupResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABSetupResponseMethodUnmarshalAPERLegacy(v *ERABSetupResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeERABSetupResponseMethodUnmarshalAPERWithOptions(v *ERABSetupResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeERABSetupResponseValueCodecFieldCapture(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, aper.DecodeState) (ERABSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseValueCodecFieldCompare(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseValueCodecFieldContext(v *ERABSetupResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseValueCodecFieldDecode(v *ERABSetupResponseValueCodec) *func([]byte, aper.DecodeState) (ERABSetupResponse, error) {
	return &v.decode
}
func BridgeERABSetupResponseValueCodecFieldEncode(v *ERABSetupResponseValueCodec) *func(ERABSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseValueCodecFieldPath(v *ERABSetupResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABSetupResponseValueCodecMethodEncodeBudgetValue(v ERABSetupResponseValueCodec, a0 ERABSetupResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABSetupResponseValueCodecMethodEncodeChanged(v ERABSetupResponseValueCodec, a0 ERABSetupResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldGet(v *PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBindingFieldInject(v *PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) *func(s00.AdditionalRRMPriorityIndex) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) *s00.AerialUEsubscriptionInformationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldGet(v *PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBindingFieldInject(v *PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) *func(s00.AerialUEsubscriptionInformation) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldGet(v *PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeCEModeBRestrictedIEBindingFieldInject(v *PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldGet(v *PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeCSGMembershipStatusIEBindingFieldInject(v *PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldGet(v *PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeENBUES1APIDIEBindingFieldInject(v *PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) *func(s00.ENBUES1APID) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeERABListIEBinding) *s16.ERABListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldGet(v *PathSwitchRequestAcknowledgeERABListIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s16.ERABList, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeERABListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeERABListIEBindingFieldInject(v *PathSwitchRequestAcknowledgeERABListIEBinding) *func(s16.ERABList) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) *s17.ERABToBeSwitchedULListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldGet(v *PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s17.ERABToBeSwitchedULList, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBindingFieldInject(v *PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) *func(s17.ERABToBeSwitchedULList) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) *s29.ERABToBeUpdatedListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldGet(v *PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s29.ERABToBeUpdatedList, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeERABToBeUpdatedListIEBindingFieldInject(v *PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) *func(s29.ERABToBeUpdatedList) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldGet(v *PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBindingFieldInject(v *PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) *s42.HandoverRestrictionListValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldGet(v *PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s42.HandoverRestrictionList, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeHandoverRestrictionListIEBindingFieldInject(v *PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) *func(s42.HandoverRestrictionList) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeIEContainerAPERValueFieldContext(v *PathSwitchRequestAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEContainerAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEContainerAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *func(PathSwitchRequestAcknowledgeIEContainer, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *func(PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldContext(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *func(PathSwitchRequestAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecFieldPath(v *PathSwitchRequestAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeIEContainerValueCodec, a0 PathSwitchRequestAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeIEContainerValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeIEContainerValueCodec, a0 PathSwitchRequestAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeIEFieldAPERValueFieldContext(v *PathSwitchRequestAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEFieldAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEFieldAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEFieldFieldReceived(v *PathSwitchRequestAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEFieldFieldReplay(v *PathSwitchRequestAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEFieldFieldStream(v *PathSwitchRequestAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePathSwitchRequestAcknowledgeIEFieldFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(v *PathSwitchRequestAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *PathSwitchRequestAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *func(PathSwitchRequestAcknowledgeIEField, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *func(PathSwitchRequestAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldContext(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *func(PathSwitchRequestAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecFieldPath(v *PathSwitchRequestAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeIEFieldValueCodec, a0 PathSwitchRequestAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeIEFieldValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeIEFieldValueCodec, a0 PathSwitchRequestAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoAdditionalRRMPriorityIndex(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoAerialUEsubscriptionInformation(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCEModeBRestricted(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCSGMembershipStatus(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoCriticalityDiagnostics(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoENBUES1APID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeReleasedList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeReleasedList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeSwitchedULList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeSwitchedULList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoERABToBeUpdatedList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoERABToBeUpdatedList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoEnhancedCoverageRestricted(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoHandoverRestrictionList(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoHandoverRestrictionList()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoMMEUES1APID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoMMEUES1APID2(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoMMEUES1APID2()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRUESecurityCapabilities(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoNRV2XServicesAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoPC5QoSParameters(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoPendingDataIndication(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoProSeAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoSecurityContext(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoSecurityContext()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoTimeRefDistribution(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUERadioCapabilityID(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUESecurityCapabilities(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUESidelinkAggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUEUserPlaneCIoTSupportIndicator(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUEUserPlaneCIoTSupportIndicator()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoUEaggregateMaximumBitrate(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgePathSwitchRequestAcknowledgeIETableMethodInfoV2XServicesAuthorized(v PathSwitchRequestAcknowledgeIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldId(v *PathSwitchRequestAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldIsOpaque(v *PathSwitchRequestAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldOpaque(v *PathSwitchRequestAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldReceived(v *PathSwitchRequestAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldReplay(v *PathSwitchRequestAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(v *PathSwitchRequestAcknowledgeIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(v *PathSwitchRequestAcknowledgeIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(v *PathSwitchRequestAcknowledgeIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(v *PathSwitchRequestAcknowledgeIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *PathSwitchRequestAcknowledgeIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(v *PathSwitchRequestAcknowledgeIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(v *PathSwitchRequestAcknowledgeIEValue) **s16.ERABList {
	return &v.rowERABToBeReleasedList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(v *PathSwitchRequestAcknowledgeIEValue) **s17.ERABToBeSwitchedULList {
	return &v.rowERABToBeSwitchedULList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(v *PathSwitchRequestAcknowledgeIEValue) **s29.ERABToBeUpdatedList {
	return &v.rowERABToBeUpdatedList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(v *PathSwitchRequestAcknowledgeIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(v *PathSwitchRequestAcknowledgeIEValue) **s42.HandoverRestrictionList {
	return &v.rowHandoverRestrictionList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(v *PathSwitchRequestAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(v *PathSwitchRequestAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID2
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(v *PathSwitchRequestAcknowledgeIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s19.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **s19.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(v *PathSwitchRequestAcknowledgeIEValue) **s24.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(v *PathSwitchRequestAcknowledgeIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **s20.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(v *PathSwitchRequestAcknowledgeIEValue) **s28.SecurityContext {
	return &v.rowSecurityContext
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *PathSwitchRequestAcknowledgeIEValue) **s30.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(v *PathSwitchRequestAcknowledgeIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(v *PathSwitchRequestAcknowledgeIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(v *PathSwitchRequestAcknowledgeIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s37.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(v *PathSwitchRequestAcknowledgeIEValue) **s00.UEUserPlaneCIoTSupportIndicator {
	return &v.rowUEUserPlaneCIoTSupportIndicator
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodCaptureSemantics(v PathSwitchRequestAcknowledgeIEValue, a0 aper.SemanticCapture) PathSwitchRequestAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodCompareSemantics(v PathSwitchRequestAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodDecode(v PathSwitchRequestAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PathSwitchRequestAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodEncode(v PathSwitchRequestAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodEncodeFresh(v PathSwitchRequestAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodMatchesID(v PathSwitchRequestAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodReason(v PathSwitchRequestAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodRule(v PathSwitchRequestAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldGet(v *PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeMMEUES1APIDIEBindingFieldInject(v *PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) *s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) *func(s19.NRUESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) *s19.NRV2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldGet(v *PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s19.NRV2XServicesAuthorized, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBindingFieldInject(v *PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) *func(s19.NRV2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldCodec(v *PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) *s24.PC5QoSParametersValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldGet(v *PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s24.PC5QoSParameters, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldInfo(v *PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgePC5QoSParametersIEBindingFieldInject(v *PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) *func(s24.PC5QoSParameters) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldCodec(v *PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldGet(v *PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldInfo(v *PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgePendingDataIndicationIEBindingFieldInject(v *PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) *func(s00.PendingDataIndication) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) *s20.ProSeAuthorizedValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldGet(v *PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s20.ProSeAuthorized, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeProSeAuthorizedIEBindingFieldInject(v *PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) *func(s20.ProSeAuthorized) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeSecurityContextIEBinding) *s28.SecurityContextValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldGet(v *PathSwitchRequestAcknowledgeSecurityContextIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s28.SecurityContext, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeSecurityContextIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeSecurityContextIEBindingFieldInject(v *PathSwitchRequestAcknowledgeSecurityContextIEBinding) *func(s28.SecurityContext) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) *s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s30.SubscriptionBasedUEDifferentiationInfo) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) *s02.TimeRefDistributionValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldGet(v *PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.TimeRefDistribution, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeTimeRefDistributionIEBindingFieldInject(v *PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) *func(s00.TimeRefDistribution) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldGet(v *PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBindingFieldInject(v *PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldGet(v *PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeUERadioCapabilityIDIEBindingFieldInject(v *PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldGet(v *PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBindingFieldInject(v *PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) *s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) *func(s37.UESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) *s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldGet(v *PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBindingFieldInject(v *PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) *func(s00.UEUserPlaneCIoTSupportIndicator) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldCodec(v *PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) *V2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldGet(v *PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) *func(*PathSwitchRequestAcknowledgeIEValue) (*V2XServicesAuthorized, bool) {
	return &v.get
}
func BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldInfo(v *PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBindingFieldInject(v *PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) *func(V2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
	return &v.inject
}
func BridgeSecondaryRATDataUsageReportAPERValueFieldContext(v *SecondaryRATDataUsageReportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportAPERValueFieldReceived(v *SecondaryRATDataUsageReportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportAPERValueFieldReplay(v *SecondaryRATDataUsageReportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportAPERValueFieldWithoutReplay(v *SecondaryRATDataUsageReportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportFieldExtCount(v *SecondaryRATDataUsageReport) *int64 {
	return &v.extCount
}
func BridgeSecondaryRATDataUsageReportFieldExtData(v *SecondaryRATDataUsageReport) *[][]byte {
	return &v.extData
}
func BridgeSecondaryRATDataUsageReportFieldExtOrigin(v *SecondaryRATDataUsageReport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSecondaryRATDataUsageReportFieldExtPresent(v *SecondaryRATDataUsageReport) *[]bool {
	return &v.extPresent
}
func BridgeSecondaryRATDataUsageReportFieldExtWire(v *SecondaryRATDataUsageReport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSecondaryRATDataUsageReportFieldPerExtPadding(v *SecondaryRATDataUsageReport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSecondaryRATDataUsageReportFieldPerPadding(v *SecondaryRATDataUsageReport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSecondaryRATDataUsageReportFieldProtocolIEsIndef(v *SecondaryRATDataUsageReport) *bool {
	return &v.protocolIEsIndef
}
func BridgeSecondaryRATDataUsageReportFieldReceived(v *SecondaryRATDataUsageReport) *bool {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportFieldReceivedAbsolute(v *SecondaryRATDataUsageReport) *bool {
	return &v.receivedAbsolute
}
func BridgeSecondaryRATDataUsageReportFieldReceivedBytes(v *SecondaryRATDataUsageReport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecondaryRATDataUsageReportFieldReceivedLocation(v *SecondaryRATDataUsageReport) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecondaryRATDataUsageReportFieldReplay(v *SecondaryRATDataUsageReport) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportFieldStream(v *SecondaryRATDataUsageReport) *aper.WireSpan {
	return &v.stream
}
func BridgeSecondaryRATDataUsageReportFieldWithoutReplay(v *SecondaryRATDataUsageReport) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v *SecondaryRATDataUsageReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudgetValue(v *SecondaryRATDataUsageReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERChanged(v *SecondaryRATDataUsageReport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERChangedValue(v *SecondaryRATDataUsageReport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERLegacy(v *SecondaryRATDataUsageReport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERNewValue(v *SecondaryRATDataUsageReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERPlanned(v *SecondaryRATDataUsageReport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportMethodMarshalAPERTo(v *SecondaryRATDataUsageReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERFrom(v *SecondaryRATDataUsageReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERLegacy(v *SecondaryRATDataUsageReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecondaryRATDataUsageReportMethodUnmarshalAPERWithOptions(v *SecondaryRATDataUsageReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldCapture(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, aper.DecodeState) (SecondaryRATDataUsageReport, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldCompare(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldContext(v *SecondaryRATDataUsageReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldDecode(v *SecondaryRATDataUsageReportValueCodec) *func([]byte, aper.DecodeState) (SecondaryRATDataUsageReport, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldEncode(v *SecondaryRATDataUsageReportValueCodec) *func(SecondaryRATDataUsageReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageReportValueCodecFieldPath(v *SecondaryRATDataUsageReportValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageReportValueCodecMethodEncodeBudgetValue(v SecondaryRATDataUsageReportValueCodec, a0 SecondaryRATDataUsageReport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportValueCodecMethodEncodeChanged(v SecondaryRATDataUsageReportValueCodec, a0 SecondaryRATDataUsageReport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldCodec(v *UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) *s00.AdditionalCSFallbackIndicatorValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldGet(v *UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldInfo(v *UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestAdditionalCSFallbackIndicatorIEBindingFieldInject(v *UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) *func(s00.AdditionalCSFallbackIndicator) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldCodec(v *UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldGet(v *UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldInfo(v *UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestAdditionalRRMPriorityIndexIEBindingFieldInject(v *UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) *func(s00.AdditionalRRMPriorityIndex) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldCodec(v *UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) *s00.AerialUEsubscriptionInformationValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldGet(v *UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldInfo(v *UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestAerialUEsubscriptionInformationIEBindingFieldInject(v *UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) *func(s00.AerialUEsubscriptionInformation) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldCodec(v *UEContextModificationRequestCSFallbackIndicatorIEBinding) *s00.CSFallbackIndicatorValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldGet(v *UEContextModificationRequestCSFallbackIndicatorIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.CSFallbackIndicator, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldInfo(v *UEContextModificationRequestCSFallbackIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestCSFallbackIndicatorIEBindingFieldInject(v *UEContextModificationRequestCSFallbackIndicatorIEBinding) *func(s00.CSFallbackIndicator) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldCodec(v *UEContextModificationRequestCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldGet(v *UEContextModificationRequestCSGMembershipStatusIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldInfo(v *UEContextModificationRequestCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestCSGMembershipStatusIEBindingFieldInject(v *UEContextModificationRequestCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldCodec(v *UEContextModificationRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldGet(v *UEContextModificationRequestENBUES1APIDIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldInfo(v *UEContextModificationRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestENBUES1APIDIEBindingFieldInject(v *UEContextModificationRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldCodec(v *UEContextModificationRequestIABAuthorizedIEBinding) *s00.IABAuthorizedValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldGet(v *UEContextModificationRequestIABAuthorizedIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.IABAuthorized, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldInfo(v *UEContextModificationRequestIABAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestIABAuthorizedIEBindingFieldInject(v *UEContextModificationRequestIABAuthorizedIEBinding) *func(s00.IABAuthorized) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestIEContainerAPERValueFieldContext(v *UEContextModificationRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEContainerAPERValueFieldReceived(v *UEContextModificationRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEContainerAPERValueFieldReplay(v *UEContextModificationRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEContainerAPERValueFieldWithoutReplay(v *UEContextModificationRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldCapture(v *UEContextModificationRequestIEContainerValueCodec) *func(UEContextModificationRequestIEContainer, aper.DecodeState) (UEContextModificationRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldCompare(v *UEContextModificationRequestIEContainerValueCodec) *func(UEContextModificationRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldContext(v *UEContextModificationRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldDecode(v *UEContextModificationRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequestIEContainer, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldEncode(v *UEContextModificationRequestIEContainerValueCodec) *func(UEContextModificationRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestIEContainerValueCodecFieldPath(v *UEContextModificationRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestIEContainerValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestIEContainerValueCodec, a0 UEContextModificationRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestIEContainerValueCodecMethodEncodeChanged(v UEContextModificationRequestIEContainerValueCodec, a0 UEContextModificationRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestIEFieldAPERValueFieldContext(v *UEContextModificationRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEFieldAPERValueFieldReceived(v *UEContextModificationRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEFieldAPERValueFieldReplay(v *UEContextModificationRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEFieldAPERValueFieldWithoutReplay(v *UEContextModificationRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEFieldFieldReceived(v *UEContextModificationRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextModificationRequestIEFieldFieldReplay(v *UEContextModificationRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEFieldFieldStream(v *UEContextModificationRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationRequestIEFieldFieldWithoutReplay(v *UEContextModificationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(v *UEContextModificationRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationRequestIEFieldMethodUnmarshalAPERFrom(v *UEContextModificationRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldCapture(v *UEContextModificationRequestIEFieldValueCodec) *func(UEContextModificationRequestIEField, aper.DecodeState) (UEContextModificationRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldCompare(v *UEContextModificationRequestIEFieldValueCodec) *func(UEContextModificationRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldContext(v *UEContextModificationRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldDecode(v *UEContextModificationRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequestIEField, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldEncode(v *UEContextModificationRequestIEFieldValueCodec) *func(UEContextModificationRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestIEFieldValueCodecFieldPath(v *UEContextModificationRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestIEFieldValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestIEFieldValueCodec, a0 UEContextModificationRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestIEFieldValueCodecMethodEncodeChanged(v UEContextModificationRequestIEFieldValueCodec, a0 UEContextModificationRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestIETableMethodInfoAdditionalCSFallbackIndicator(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAdditionalCSFallbackIndicator()
}
func BridgeUEContextModificationRequestIETableMethodInfoAdditionalRRMPriorityIndex(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeUEContextModificationRequestIETableMethodInfoAerialUEsubscriptionInformation(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgeUEContextModificationRequestIETableMethodInfoCSFallbackIndicator(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoCSFallbackIndicator()
}
func BridgeUEContextModificationRequestIETableMethodInfoCSGMembershipStatus(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeUEContextModificationRequestIETableMethodInfoENBUES1APID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextModificationRequestIETableMethodInfoIABAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoIABAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoMMEUES1APID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRUESecurityCapabilities(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoNRV2XServicesAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoPC5QoSParameters(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgeUEContextModificationRequestIETableMethodInfoProSeAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgeUEContextModificationRequestIETableMethodInfoRegisteredLAI(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoRegisteredLAI()
}
func BridgeUEContextModificationRequestIETableMethodInfoSRVCCOperationNotPossible(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationNotPossible()
}
func BridgeUEContextModificationRequestIETableMethodInfoSRVCCOperationPossible(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationPossible()
}
func BridgeUEContextModificationRequestIETableMethodInfoSecurityKey(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSecurityKey()
}
func BridgeUEContextModificationRequestIETableMethodInfoSubscriberProfileIDforRFP(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoSubscriberProfileIDforRFP()
}
func BridgeUEContextModificationRequestIETableMethodInfoTimeRefDistribution(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgeUEContextModificationRequestIETableMethodInfoUERadioCapabilityID(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeUEContextModificationRequestIETableMethodInfoUESecurityCapabilities(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgeUEContextModificationRequestIETableMethodInfoUESidelinkAggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoUEaggregateMaximumBitrate(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeUEContextModificationRequestIETableMethodInfoV2XServicesAuthorized(v UEContextModificationRequestIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListAPERValueFieldContext(v *UEContextModificationRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextModificationRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextModificationRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *func(UEContextModificationRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *func(UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldContext(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *func(UEContextModificationRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecFieldPath(v *UEContextModificationRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestIEValueERABIEContainerListValueCodec, a0 UEContextModificationRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationRequestIEValueERABIEContainerListValueCodec, a0 UEContextModificationRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestIEValueFieldId(v *UEContextModificationRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationRequestIEValueFieldIsOpaque(v *UEContextModificationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationRequestIEValueFieldOpaque(v *UEContextModificationRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationRequestIEValueFieldReceived(v *UEContextModificationRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEValueFieldReplay(v *UEContextModificationRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(v *UEContextModificationRequestIEValue) **s00.AdditionalCSFallbackIndicator {
	return &v.rowAdditionalCSFallbackIndicator
}
func BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(v *UEContextModificationRequestIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(v *UEContextModificationRequestIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(v *UEContextModificationRequestIEValue) **s00.CSFallbackIndicator {
	return &v.rowCSFallbackIndicator
}
func BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(v *UEContextModificationRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(v *UEContextModificationRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(v *UEContextModificationRequestIEValue) **s00.IABAuthorized {
	return &v.rowIABAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(v *UEContextModificationRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(v *UEContextModificationRequestIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s19.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(v *UEContextModificationRequestIEValue) **s19.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(v *UEContextModificationRequestIEValue) **s24.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(v *UEContextModificationRequestIEValue) **s20.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(v *UEContextModificationRequestIEValue) **s18.LAI {
	return &v.rowRegisteredLAI
}
func BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(v *UEContextModificationRequestIEValue) **s00.SRVCCOperationNotPossible {
	return &v.rowSRVCCOperationNotPossible
}
func BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(v *UEContextModificationRequestIEValue) **s00.SRVCCOperationPossible {
	return &v.rowSRVCCOperationPossible
}
func BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(v *UEContextModificationRequestIEValue) **s00.SecurityKey {
	return &v.rowSecurityKey
}
func BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(v *UEContextModificationRequestIEValue) **s00.SubscriberProfileIDforRFP {
	return &v.rowSubscriberProfileIDforRFP
}
func BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(v *UEContextModificationRequestIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(v *UEContextModificationRequestIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(v *UEContextModificationRequestIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s37.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s35.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(v *UEContextModificationRequestIEValue) **V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgeUEContextModificationRequestIEValueMethodCaptureSemantics(v UEContextModificationRequestIEValue, a0 aper.SemanticCapture) UEContextModificationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextModificationRequestIEValueMethodCompareSemantics(v UEContextModificationRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextModificationRequestIEValueMethodDecode(v UEContextModificationRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextModificationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextModificationRequestIEValueMethodEncode(v UEContextModificationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextModificationRequestIEValueMethodEncodeFresh(v UEContextModificationRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationRequestIEValueMethodMatchesID(v UEContextModificationRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationRequestIEValueMethodReason(v UEContextModificationRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextModificationRequestIEValueMethodRule(v UEContextModificationRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextModificationRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextModificationRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextModificationRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextModificationRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextModificationRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationRequestLAIIEBindingFieldCodec(v *UEContextModificationRequestLAIIEBinding) *s18.LAIValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestLAIIEBindingFieldGet(v *UEContextModificationRequestLAIIEBinding) *func(*UEContextModificationRequestIEValue) (*s18.LAI, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestLAIIEBindingFieldInfo(v *UEContextModificationRequestLAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestLAIIEBindingFieldInject(v *UEContextModificationRequestLAIIEBinding) *func(s18.LAI) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldCodec(v *UEContextModificationRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldGet(v *UEContextModificationRequestMMEUES1APIDIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldInfo(v *UEContextModificationRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestMMEUES1APIDIEBindingFieldInject(v *UEContextModificationRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldCodec(v *UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldGet(v *UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) *func(*UEContextModificationRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldInfo(v *UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestNRUESecurityCapabilitiesIEBindingFieldInject(v *UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s19.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(*UEContextModificationRequestIEValue) (*s19.NRUESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(s19.NRUESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldCodec(v *UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) *s19.NRV2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldGet(v *UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) *func(*UEContextModificationRequestIEValue) (*s19.NRV2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldInfo(v *UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestNRV2XServicesAuthorizedIEBindingFieldInject(v *UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) *func(s19.NRV2XServicesAuthorized) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldCodec(v *UEContextModificationRequestPC5QoSParametersIEBinding) *s24.PC5QoSParametersValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldGet(v *UEContextModificationRequestPC5QoSParametersIEBinding) *func(*UEContextModificationRequestIEValue) (*s24.PC5QoSParameters, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldInfo(v *UEContextModificationRequestPC5QoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestPC5QoSParametersIEBindingFieldInject(v *UEContextModificationRequestPC5QoSParametersIEBinding) *func(s24.PC5QoSParameters) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldCodec(v *UEContextModificationRequestProSeAuthorizedIEBinding) *s20.ProSeAuthorizedValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldGet(v *UEContextModificationRequestProSeAuthorizedIEBinding) *func(*UEContextModificationRequestIEValue) (*s20.ProSeAuthorized, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldInfo(v *UEContextModificationRequestProSeAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestProSeAuthorizedIEBindingFieldInject(v *UEContextModificationRequestProSeAuthorizedIEBinding) *func(s20.ProSeAuthorized) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldCodec(v *UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) *s01.SRVCCOperationNotPossibleValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldGet(v *UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.SRVCCOperationNotPossible, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldInfo(v *UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestSRVCCOperationNotPossibleIEBindingFieldInject(v *UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) *func(s00.SRVCCOperationNotPossible) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldCodec(v *UEContextModificationRequestSRVCCOperationPossibleIEBinding) *s01.SRVCCOperationPossibleValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldGet(v *UEContextModificationRequestSRVCCOperationPossibleIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldInfo(v *UEContextModificationRequestSRVCCOperationPossibleIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestSRVCCOperationPossibleIEBindingFieldInject(v *UEContextModificationRequestSRVCCOperationPossibleIEBinding) *func(s00.SRVCCOperationPossible) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestSecurityKeyIEBindingFieldCodec(v *UEContextModificationRequestSecurityKeyIEBinding) *s01.SecurityKeyValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestSecurityKeyIEBindingFieldGet(v *UEContextModificationRequestSecurityKeyIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.SecurityKey, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestSecurityKeyIEBindingFieldInfo(v *UEContextModificationRequestSecurityKeyIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestSecurityKeyIEBindingFieldInject(v *UEContextModificationRequestSecurityKeyIEBinding) *func(s00.SecurityKey) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldCodec(v *UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) *s01.SubscriberProfileIDforRFPValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldGet(v *UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldInfo(v *UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestSubscriberProfileIDforRFPIEBindingFieldInject(v *UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) *func(s00.SubscriberProfileIDforRFP) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldCodec(v *UEContextModificationRequestTimeRefDistributionIEBinding) *s02.TimeRefDistributionValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldGet(v *UEContextModificationRequestTimeRefDistributionIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.TimeRefDistribution, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldInfo(v *UEContextModificationRequestTimeRefDistributionIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestTimeRefDistributionIEBindingFieldInject(v *UEContextModificationRequestTimeRefDistributionIEBinding) *func(s00.TimeRefDistribution) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldCodec(v *UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) *s35.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldGet(v *UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) *func(*UEContextModificationRequestIEValue) (*s35.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldInfo(v *UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestUEAggregateMaximumBitrateIEBindingFieldInject(v *UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) *func(s35.UEAggregateMaximumBitrate) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldCodec(v *UEContextModificationRequestUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldGet(v *UEContextModificationRequestUERadioCapabilityIDIEBinding) *func(*UEContextModificationRequestIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldInfo(v *UEContextModificationRequestUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestUERadioCapabilityIDIEBindingFieldInject(v *UEContextModificationRequestUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldCodec(v *UEContextModificationRequestUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldGet(v *UEContextModificationRequestUESecurityCapabilitiesIEBinding) *func(*UEContextModificationRequestIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldInfo(v *UEContextModificationRequestUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestUESecurityCapabilitiesIEBindingFieldInject(v *UEContextModificationRequestUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) *s37.UESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(*UEContextModificationRequestIEValue) (*s37.UESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(s37.UESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldCodec(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *V2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldGet(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *func(*UEContextModificationRequestIEValue) (*V2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldInfo(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextModificationRequestV2XServicesAuthorizedIEBindingFieldInject(v *UEContextModificationRequestV2XServicesAuthorizedIEBinding) *func(V2XServicesAuthorized) UEContextModificationRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteAPERValueFieldContext(v *UEContextReleaseCompleteAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteAPERValueFieldReceived(v *UEContextReleaseCompleteAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCompleteAPERValueFieldReplay(v *UEContextReleaseCompleteAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteAPERValueFieldWithoutReplay(v *UEContextReleaseCompleteAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteFieldExtCount(v *UEContextReleaseComplete) *int64 {
	return &v.extCount
}
func BridgeUEContextReleaseCompleteFieldExtData(v *UEContextReleaseComplete) *[][]byte {
	return &v.extData
}
func BridgeUEContextReleaseCompleteFieldExtOrigin(v *UEContextReleaseComplete) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextReleaseCompleteFieldExtPresent(v *UEContextReleaseComplete) *[]bool {
	return &v.extPresent
}
func BridgeUEContextReleaseCompleteFieldExtWire(v *UEContextReleaseComplete) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextReleaseCompleteFieldPerExtPadding(v *UEContextReleaseComplete) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextReleaseCompleteFieldPerPadding(v *UEContextReleaseComplete) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseCompleteFieldProtocolIEsIndef(v *UEContextReleaseComplete) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextReleaseCompleteFieldReceived(v *UEContextReleaseComplete) *bool {
	return &v.received
}
func BridgeUEContextReleaseCompleteFieldReceivedAbsolute(v *UEContextReleaseComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseCompleteFieldReceivedBytes(v *UEContextReleaseComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseCompleteFieldReceivedLocation(v *UEContextReleaseComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseCompleteFieldReplay(v *UEContextReleaseComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCompleteFieldStream(v *UEContextReleaseComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCompleteFieldWithoutReplay(v *UEContextReleaseComplete) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v *UEContextReleaseComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERBudgetValue(v *UEContextReleaseComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERChanged(v *UEContextReleaseComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERChangedValue(v *UEContextReleaseComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERLegacy(v *UEContextReleaseComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERNewValue(v *UEContextReleaseComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERPlanned(v *UEContextReleaseComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteMethodMarshalAPERTo(v *UEContextReleaseComplete, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCompleteMethodUnmarshalAPERFrom(v *UEContextReleaseComplete, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCompleteMethodUnmarshalAPERLegacy(v *UEContextReleaseComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextReleaseCompleteMethodUnmarshalAPERWithOptions(v *UEContextReleaseComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseCompleteValueCodecFieldCapture(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, aper.DecodeState) (UEContextReleaseComplete, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteValueCodecFieldCompare(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteValueCodecFieldContext(v *UEContextReleaseCompleteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteValueCodecFieldDecode(v *UEContextReleaseCompleteValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseComplete, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteValueCodecFieldEncode(v *UEContextReleaseCompleteValueCodec) *func(UEContextReleaseComplete, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteValueCodecFieldPath(v *UEContextReleaseCompleteValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCompleteValueCodecMethodEncodeBudgetValue(v UEContextReleaseCompleteValueCodec, a0 UEContextReleaseComplete, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCompleteValueCodecMethodEncodeChanged(v UEContextReleaseCompleteValueCodec, a0 UEContextReleaseComplete, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendRequestAPERValueFieldContext(v *UEContextSuspendRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestAPERValueFieldReceived(v *UEContextSuspendRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendRequestAPERValueFieldReplay(v *UEContextSuspendRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestAPERValueFieldWithoutReplay(v *UEContextSuspendRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestFieldExtCount(v *UEContextSuspendRequest) *int64 {
	return &v.extCount
}
func BridgeUEContextSuspendRequestFieldExtData(v *UEContextSuspendRequest) *[][]byte {
	return &v.extData
}
func BridgeUEContextSuspendRequestFieldExtOrigin(v *UEContextSuspendRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextSuspendRequestFieldExtPresent(v *UEContextSuspendRequest) *[]bool {
	return &v.extPresent
}
func BridgeUEContextSuspendRequestFieldExtWire(v *UEContextSuspendRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextSuspendRequestFieldPerExtPadding(v *UEContextSuspendRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextSuspendRequestFieldPerPadding(v *UEContextSuspendRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextSuspendRequestFieldProtocolIEsIndef(v *UEContextSuspendRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextSuspendRequestFieldReceived(v *UEContextSuspendRequest) *bool { return &v.received }
func BridgeUEContextSuspendRequestFieldReceivedAbsolute(v *UEContextSuspendRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextSuspendRequestFieldReceivedBytes(v *UEContextSuspendRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextSuspendRequestFieldReceivedLocation(v *UEContextSuspendRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextSuspendRequestFieldReplay(v *UEContextSuspendRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendRequestFieldStream(v *UEContextSuspendRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextSuspendRequestFieldWithoutReplay(v *UEContextSuspendRequest) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v *UEContextSuspendRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERBudgetValue(v *UEContextSuspendRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERChanged(v *UEContextSuspendRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERChangedValue(v *UEContextSuspendRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERLegacy(v *UEContextSuspendRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextSuspendRequestMethodMarshalAPERNewValue(v *UEContextSuspendRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERPlanned(v *UEContextSuspendRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextSuspendRequestMethodMarshalAPERTo(v *UEContextSuspendRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextSuspendRequestMethodUnmarshalAPERFrom(v *UEContextSuspendRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextSuspendRequestMethodUnmarshalAPERLegacy(v *UEContextSuspendRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextSuspendRequestMethodUnmarshalAPERWithOptions(v *UEContextSuspendRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextSuspendRequestValueCodecFieldCapture(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, aper.DecodeState) (UEContextSuspendRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendRequestValueCodecFieldCompare(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendRequestValueCodecFieldContext(v *UEContextSuspendRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendRequestValueCodecFieldDecode(v *UEContextSuspendRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendRequest, error) {
	return &v.decode
}
func BridgeUEContextSuspendRequestValueCodecFieldEncode(v *UEContextSuspendRequestValueCodec) *func(UEContextSuspendRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendRequestValueCodecFieldPath(v *UEContextSuspendRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendRequestValueCodecMethodEncodeBudgetValue(v UEContextSuspendRequestValueCodec, a0 UEContextSuspendRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendRequestValueCodecMethodEncodeChanged(v UEContextSuspendRequestValueCodec, a0 UEContextSuspendRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeV2XServicesAuthorizedAPERValueFieldContext(v *V2XServicesAuthorizedAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeV2XServicesAuthorizedAPERValueFieldReceived(v *V2XServicesAuthorizedAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeV2XServicesAuthorizedAPERValueFieldReplay(v *V2XServicesAuthorizedAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeV2XServicesAuthorizedAPERValueFieldWithoutReplay(v *V2XServicesAuthorizedAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeV2XServicesAuthorizedFieldExtCount(v *V2XServicesAuthorized) *int64   { return &v.extCount }
func BridgeV2XServicesAuthorizedFieldExtData(v *V2XServicesAuthorized) *[][]byte { return &v.extData }
func BridgeV2XServicesAuthorizedFieldExtOrigin(v *V2XServicesAuthorized) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeV2XServicesAuthorizedFieldExtPresent(v *V2XServicesAuthorized) *[]bool {
	return &v.extPresent
}
func BridgeV2XServicesAuthorizedFieldExtWire(v *V2XServicesAuthorized) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeV2XServicesAuthorizedFieldIEExtensionsIndef(v *V2XServicesAuthorized) *bool {
	return &v.iEExtensionsIndef
}
func BridgeV2XServicesAuthorizedFieldPerExtPadding(v *V2XServicesAuthorized) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeV2XServicesAuthorizedFieldPerPadding(v *V2XServicesAuthorized) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeV2XServicesAuthorizedFieldReceived(v *V2XServicesAuthorized) *bool { return &v.received }
func BridgeV2XServicesAuthorizedFieldReceivedAbsolute(v *V2XServicesAuthorized) *bool {
	return &v.receivedAbsolute
}
func BridgeV2XServicesAuthorizedFieldReceivedBytes(v *V2XServicesAuthorized) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeV2XServicesAuthorizedFieldReceivedLocation(v *V2XServicesAuthorized) *aper.Location {
	return &v.receivedLocation
}
func BridgeV2XServicesAuthorizedFieldReplay(v *V2XServicesAuthorized) *aper.Snapshot {
	return &v.replay
}
func BridgeV2XServicesAuthorizedFieldStream(v *V2XServicesAuthorized) *aper.WireSpan {
	return &v.stream
}
func BridgeV2XServicesAuthorizedFieldWithoutReplay(v *V2XServicesAuthorized) *bool {
	return &v.withoutReplay
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v *V2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERBudgetValue(v *V2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERChanged(v *V2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERChangedValue(v *V2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERLegacy(v *V2XServicesAuthorized) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERNewValue(v *V2XServicesAuthorized, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERPlanned(v *V2XServicesAuthorized, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeV2XServicesAuthorizedMethodMarshalAPERTo(v *V2XServicesAuthorized, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(v *V2XServicesAuthorized, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeV2XServicesAuthorizedMethodUnmarshalAPERLegacy(v *V2XServicesAuthorized, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeV2XServicesAuthorizedMethodUnmarshalAPERWithOptions(v *V2XServicesAuthorized, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeV2XServicesAuthorizedValueCodecFieldCapture(v *V2XServicesAuthorizedValueCodec) *func(V2XServicesAuthorized, aper.DecodeState) (V2XServicesAuthorized, aper.Snapshot) {
	return &v.capture
}
func BridgeV2XServicesAuthorizedValueCodecFieldCompare(v *V2XServicesAuthorizedValueCodec) *func(V2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeV2XServicesAuthorizedValueCodecFieldContext(v *V2XServicesAuthorizedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeV2XServicesAuthorizedValueCodecFieldDecode(v *V2XServicesAuthorizedValueCodec) *func([]byte, aper.DecodeState) (V2XServicesAuthorized, error) {
	return &v.decode
}
func BridgeV2XServicesAuthorizedValueCodecFieldEncode(v *V2XServicesAuthorizedValueCodec) *func(V2XServicesAuthorized, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeV2XServicesAuthorizedValueCodecFieldPath(v *V2XServicesAuthorizedValueCodec) *aper.Path {
	return &v.path
}
func BridgeV2XServicesAuthorizedValueCodecMethodEncodeBudgetValue(v V2XServicesAuthorizedValueCodec, a0 V2XServicesAuthorized, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeV2XServicesAuthorizedValueCodecMethodEncodeChanged(v V2XServicesAuthorizedValueCodec, a0 V2XServicesAuthorized, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
