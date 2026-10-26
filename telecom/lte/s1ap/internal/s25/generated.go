// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s25 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s25

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

type BuildError struct{ Issues []ValidationIssue }

// Unwrap returns the invalid-value error associated with the failed S1AP build.
func (e *BuildError) Unwrap() error { return aper.ErrInvalidValue }

// Error describes the first reported S1AP message-structure issue, or a generic build failure when no issue is available.
func (e *BuildError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return "S1AP build failed"
	}
	return fmt.Sprintf("S1AP build at %s: structural issue %d (IE %d)", e.Issues[0].Location.Path, e.Issues[0].Code, e.Issues[0].IEID)
}
func BridgeBuildBlockingIssues(report ValidationReport) []ValidationIssue {
	blocking := report.Issues[:0]
	for _, issue := range report.Issues {
		if report.budget != nil {
			if err := aper.NewBudgetBuffer(report.budget).ChargeWork(1); err != nil {
				return nil
			}
		}
		if issue.Severity == s00.ValidationSeverityError {
			blocking = append(blocking, issue)
		}
	}
	return blocking
}

// ENBStatusTransferIEContainer is ProtocolIE-Container {{ENBStatusTransferIEs}} of TS 36.413: a list of ENBStatusTransferIEField values.
type ENBStatusTransferIEContainer []ENBStatusTransferIEField

// ENBStatusTransferIEField is ProtocolIE-Field {{ENBStatusTransferIEs}} of TS 36.413: an information element field.
type ENBStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEField) WithoutReplay() ENBStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferIEField{}
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
	var zero ENBStatusTransferIEValue

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

// MMEStatusTransferIEContainer is ProtocolIE-Container {{MMEStatusTransferIEs}} of TS 36.413: a list of MMEStatusTransferIEField values.
type MMEStatusTransferIEContainer []MMEStatusTransferIEField

// MMEStatusTransferIEField is ProtocolIE-Field {{MMEStatusTransferIEs}} of TS 36.413: an information element field.
type MMEStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEField) WithoutReplay() MMEStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEStatusTransferIEField{}
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
	var zero MMEStatusTransferIEValue

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
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(v *BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(v *BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(v *s20.CellTrafficTraceIEContainer, s *aper.SemanticCapture) {
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
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(v *s20.CellTrafficTraceIEContainer, s *aper.SemanticComparison) {
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
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{Bearers-SubjectToStatusTransfer-ItemIEs}} of TS 36.413: a single information element field.
type BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer = BearersSubjectToStatusTransferItemIEField

// UserLocationInformationExtIEsExtContainer is ProtocolExtensionContainer {{UserLocationInformation-ExtIEs}} of TS 36.413: a list of UserLocationInformationExtIEsExtField values.
type UserLocationInformationExtIEsExtContainer []UserLocationInformationExtIEsExtField

// UserLocationInformationExtIEsExtField is ProtocolExtensionField {{UserLocationInformation-ExtIEs}} of TS 36.413: an extension field.
type UserLocationInformationExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue UserLocationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtField) WithoutReplay() UserLocationInformationExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UserLocationInformationExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UserLocationInformationExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *UserLocationInformationExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformationExtIEsExtField{}
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
	var zero UserLocationInformationExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding binds BearersSubjectToStatusTransferItem to the Bearers-SubjectToStatusTransfer-ItemIEs object set of TS 36.413.
type BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding struct {
	info   s00.FieldInfo
	codec  BearersSubjectToStatusTransferItemValueCodec
	inject func(BearersSubjectToStatusTransferItem,

	) BearersSubjectToStatusTransferItemIEValue

	get func(*BearersSubjectToStatusTransferItemIEValue,

	) (*BearersSubjectToStatusTransferItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Codec() BearersSubjectToStatusTransferItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) New(value BearersSubjectToStatusTransferItem,

) (BearersSubjectToStatusTransferItemIEField, error) {
	if b.inject == nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding) Get(field *BearersSubjectToStatusTransferItemIEField) (*BearersSubjectToStatusTransferItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToStatusTransferItemValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItem].
type BearersSubjectToStatusTransferItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItem,

		error)
	encode func(BearersSubjectToStatusTransferItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItem, aper.DecodeState,

	) (BearersSubjectToStatusTransferItem, aper.Snapshot,

	)
	compare func(BearersSubjectToStatusTransferItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemValueCodec) New(value BearersSubjectToStatusTransferItem,

) (BearersSubjectToStatusTransferItemAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemValueCodec) encodeChanged(value BearersSubjectToStatusTransferItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEField is ProtocolIE-Field {{Bearers-SubjectToStatusTransfer-ItemIEs}} of TS 36.413: an information element field.
type BearersSubjectToStatusTransferItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         BearersSubjectToStatusTransferItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEField) WithoutReplay() BearersSubjectToStatusTransferItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *BearersSubjectToStatusTransferItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *BearersSubjectToStatusTransferItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *BearersSubjectToStatusTransferItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItemIEField{}
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
	var zero BearersSubjectToStatusTransferItemIEValue

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

// UserLocationInformationExtIEsPSCellInformationExtBinding binds PSCellInformation to the UserLocationInformation-ExtIEs object set of TS 36.413.
type UserLocationInformationExtIEsPSCellInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s23.PSCellInformationValueCodec
	inject func(s23.PSCellInformation,

	) UserLocationInformationExtIEsValue

	get func(*UserLocationInformationExtIEsValue,

	) (*s23.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Codec() s23.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) New(value s23.PSCellInformation,

) (UserLocationInformationExtIEsExtField, error) {
	if b.inject == nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return UserLocationInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UserLocationInformationExtIEsPSCellInformationExtBinding) Get(field *UserLocationInformationExtIEsExtField) (*s23.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// UserLocationInformationExtIEsLTENTNTAIInformationExtBinding binds LTENTNTAIInformation to the UserLocationInformation-ExtIEs object set of TS 36.413.
type UserLocationInformationExtIEsLTENTNTAIInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s22.LTENTNTAIInformationValueCodec
	inject func(s22.LTENTNTAIInformation,

	) UserLocationInformationExtIEsValue

	get func(*UserLocationInformationExtIEsValue,

	) (*s22.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Codec() s22.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) New(value s22.LTENTNTAIInformation,

) (UserLocationInformationExtIEsExtField, error) {
	if b.inject == nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return UserLocationInformationExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UserLocationInformationExtIEsLTENTNTAIInformationExtBinding) Get(field *UserLocationInformationExtIEsExtField) (*s22.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ENBStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the ENBStatusTransferIEs object set of TS 36.413.
type ENBStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferMMEUES1APIDIEBinding) Get(field *ENBStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the ENBStatusTransferIEs object set of TS 36.413.
type ENBStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferENBUES1APIDIEBinding) Get(field *ENBStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferENBStatusTransferTransparentContainerIEBinding binds ENBStatusTransferTransparentContainer to the ENBStatusTransferIEs object set of TS 36.413.
type ENBStatusTransferENBStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBStatusTransferTransparentContainerValueCodec
	inject func(ENBStatusTransferTransparentContainer,

	) ENBStatusTransferIEValue

	get func(*ENBStatusTransferIEValue,

	) (*ENBStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Codec() ENBStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) New(value ENBStatusTransferTransparentContainer,

) (ENBStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBStatusTransferENBStatusTransferTransparentContainerIEBinding) Get(field *ENBStatusTransferIEField) (*ENBStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBStatusTransferTransparentContainerValueCodec is the concrete ValueCodec[ENBStatusTransferTransparentContainer].
type ENBStatusTransferTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferTransparentContainer,

		error)
	encode func(ENBStatusTransferTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferTransparentContainer, aper.DecodeState,

	) (ENBStatusTransferTransparentContainer, aper.Snapshot,

	)
	compare func(ENBStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferTransparentContainerValueCodec) New(value ENBStatusTransferTransparentContainer,

) (ENBStatusTransferTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferTransparentContainerValueCodec) EncodeAPER(value ENBStatusTransferTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferTransparentContainerValueCodec) encodeBudgetValue(value ENBStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferTransparentContainerValueCodec) encodeChanged(value ENBStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the MMEStatusTransferIEs object set of TS 36.413.
type MMEStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) MMEStatusTransferIEValue

	get func(*MMEStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (MMEStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEStatusTransferMMEUES1APIDIEBinding) Get(field *MMEStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the MMEStatusTransferIEs object set of TS 36.413.
type MMEStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) MMEStatusTransferIEValue

	get func(*MMEStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b MMEStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (MMEStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEStatusTransferENBUES1APIDIEBinding) Get(field *MMEStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEStatusTransferENBStatusTransferTransparentContainerIEBinding binds ENBStatusTransferTransparentContainer to the MMEStatusTransferIEs object set of TS 36.413.
type MMEStatusTransferENBStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBStatusTransferTransparentContainerValueCodec
	inject func(ENBStatusTransferTransparentContainer,

	) MMEStatusTransferIEValue

	get func(*MMEStatusTransferIEValue,

	) (*ENBStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Codec() ENBStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) New(value ENBStatusTransferTransparentContainer,

) (MMEStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEStatusTransferENBStatusTransferTransparentContainerIEBinding) Get(field *MMEStatusTransferIEField) (*ENBStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// BearersSubjectToStatusTransferListValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferList].
type BearersSubjectToStatusTransferListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferList,

		error)
	encode func(BearersSubjectToStatusTransferList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferList, aper.DecodeState,

	) (BearersSubjectToStatusTransferList, aper.Snapshot,

	)
	compare func(BearersSubjectToStatusTransferList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferListValueCodec) New(value BearersSubjectToStatusTransferList,

) (BearersSubjectToStatusTransferListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferListValueCodec) encodeChanged(value BearersSubjectToStatusTransferList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellActivationResponseValueCodec is the concrete ValueCodec[CellActivationResponse].
type CellActivationResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellActivationResponse,

		error)
	encode func(CellActivationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellActivationResponse, aper.DecodeState,

	) (CellActivationResponse, aper.Snapshot,

	)
	compare func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellActivationResponseValueCodec) New(value CellActivationResponse,

) (CellActivationResponseAPERValue, error) {
	if c.encode == nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellActivationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellActivationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellActivationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellActivationResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellActivationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellActivationResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellActivationResponseValueCodec) EncodeAPER(value CellActivationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellActivationResponseValueCodec) encodeBudgetValue(value CellActivationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellActivationResponseValueCodec) encodeChanged(value CellActivationResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedMDTValueCodec is the concrete ValueCodec[CellBasedMDT].
type CellBasedMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedMDT,

		error)
	encode func(CellBasedMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedMDT, aper.DecodeState,

	) (CellBasedMDT, aper.Snapshot,

	)
	compare func(CellBasedMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedMDTValueCodec) New(value CellBasedMDT,

) (CellBasedMDTAPERValue, error) {
	if c.encode == nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedMDTValueCodec) EncodeAPER(value CellBasedMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedMDTValueCodec) encodeBudgetValue(value CellBasedMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedMDTValueCodec) encodeChanged(value CellBasedMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellBasedQMCValueCodec is the concrete ValueCodec[CellBasedQMC].
type CellBasedQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellBasedQMC,

		error)
	encode func(CellBasedQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellBasedQMC, aper.DecodeState,

	) (CellBasedQMC, aper.Snapshot,

	)
	compare func(CellBasedQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellBasedQMCValueCodec) New(value CellBasedQMC,

) (CellBasedQMCAPERValue, error) {
	if c.encode == nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellBasedQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellBasedQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellBasedQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellBasedQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellBasedQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellBasedQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellBasedQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellBasedQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellBasedQMCValueCodec) EncodeAPER(value CellBasedQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellBasedQMCValueCodec) encodeBudgetValue(value CellBasedQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellBasedQMCValueCodec) encodeChanged(value CellBasedQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// CellTrafficTraceValueCodec is the concrete ValueCodec[CellTrafficTrace].
type CellTrafficTraceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (CellTrafficTrace,

		error)
	encode func(CellTrafficTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(CellTrafficTrace, aper.DecodeState,

	) (CellTrafficTrace, aper.Snapshot,

	)
	compare func(CellTrafficTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c CellTrafficTraceValueCodec) New(value CellTrafficTrace,

) (CellTrafficTraceAPERValue, error) {
	if c.encode == nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellTrafficTraceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return CellTrafficTraceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c CellTrafficTraceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellTrafficTraceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return CellTrafficTraceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return CellTrafficTraceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return CellTrafficTraceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return CellTrafficTraceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c CellTrafficTraceValueCodec) EncodeAPER(value CellTrafficTraceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c CellTrafficTraceValueCodec) encodeBudgetValue(value CellTrafficTrace,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c CellTrafficTraceValueCodec) encodeChanged(value CellTrafficTrace,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelled].
type EmergencyAreaIDCancelledValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelled,

		error)
	encode func(EmergencyAreaIDCancelled,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelled, aper.DecodeState,

	) (EmergencyAreaIDCancelled, aper.Snapshot,

	)
	compare func(EmergencyAreaIDCancelled, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledValueCodec) New(value EmergencyAreaIDCancelled,

) (EmergencyAreaIDCancelledAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledValueCodec) EncodeAPER(value EmergencyAreaIDCancelledAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDCancelledValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelled,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledValueCodec) encodeChanged(value EmergencyAreaIDCancelled,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EmergencyAreaIDCancelledItemValueCodec is the concrete ValueCodec[EmergencyAreaIDCancelledItem].
type EmergencyAreaIDCancelledItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (EmergencyAreaIDCancelledItem,

		error)
	encode func(EmergencyAreaIDCancelledItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(EmergencyAreaIDCancelledItem, aper.DecodeState,

	) (EmergencyAreaIDCancelledItem, aper.Snapshot,

	)
	compare func(EmergencyAreaIDCancelledItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c EmergencyAreaIDCancelledItemValueCodec) New(value EmergencyAreaIDCancelledItem,

) (EmergencyAreaIDCancelledItemAPERValue, error) {
	if c.encode == nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return EmergencyAreaIDCancelledItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c EmergencyAreaIDCancelledItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EmergencyAreaIDCancelledItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return EmergencyAreaIDCancelledItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return EmergencyAreaIDCancelledItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return EmergencyAreaIDCancelledItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return EmergencyAreaIDCancelledItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c EmergencyAreaIDCancelledItemValueCodec) EncodeAPER(value EmergencyAreaIDCancelledItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c EmergencyAreaIDCancelledItemValueCodec) encodeBudgetValue(value EmergencyAreaIDCancelledItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c EmergencyAreaIDCancelledItemValueCodec) encodeChanged(value EmergencyAreaIDCancelledItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HOReportValueCodec is the concrete ValueCodec[HOReport].
type HOReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HOReport,

		error)
	encode func(HOReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HOReport, aper.DecodeState,

	) (HOReport, aper.Snapshot,

	)
	compare func(HOReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HOReportValueCodec) New(value HOReport,

) (HOReportAPERValue, error) {
	if c.encode == nil {
		return HOReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HOReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HOReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HOReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HOReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HOReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HOReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HOReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HOReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HOReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HOReportValueCodec) EncodeAPER(value HOReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HOReportValueCodec) encodeBudgetValue(value HOReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HOReportValueCodec) encodeChanged(value HOReport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEContainer is ProtocolIE-Container {{Bearers-SubjectToStatusTransfer-ItemIEs}} of TS 36.413: a list of BearersSubjectToStatusTransferItemIEField values.
type BearersSubjectToStatusTransferItemIEContainer []BearersSubjectToStatusTransferItemIEField

// BearersSubjectToDLDiscardingItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{Bearers-SubjectToDLDiscarding-ItemIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemIEValueERABIEContainerList"
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToDLDiscardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList"
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToEarlyStatusTransferItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{Bearers-SubjectToStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemIEValueERABIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec{path: "BearersSubjectToStatusTransferItemIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields BearersSubjectToStatusTransferItemIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field BearersSubjectToStatusTransferItemIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueERABIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellTrafficTraceIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{CellTrafficTraceIEs}} codec of TS 36.413.
func CellTrafficTraceIEValueERABIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable) s20.CellTrafficTraceIEValueERABIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.CellTrafficTraceIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.CellTrafficTraceIEValueERABIEContainerListValueCodec {
		sealed := s20.CellTrafficTraceIEValueERABIEContainerListValueCodec{}
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "CellTrafficTraceIEValueERABIEContainerList"
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellTrafficTraceIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.CellTrafficTraceIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.CellTrafficTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTrafficTraceIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.CellTrafficTraceIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s20.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.CellTrafficTraceIEValueERABIEContainerList, options aper.DecodeState) (s20.CellTrafficTraceIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.CellTrafficTraceIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCellTrafficTraceIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemExtIEsValueExtensionFieldTableCodec(table s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable) s16.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec{}
	}
	return func() s16.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec {
		sealed := s16.BearersSubjectToStatusTransferItemExtIEsExtFieldValueCodec{}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldPath(&sealed) = "BearersSubjectToStatusTransferItemExtIEsExtField"
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.BearersSubjectToStatusTransferItemExtIEsExtField, error) {
			var field s16.BearersSubjectToStatusTransferItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemExtIEsExtField")
			}
			return field, nil
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s16.BearersSubjectToStatusTransferItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s16.BearersSubjectToStatusTransferItemExtIEsExtField, options aper.DecodeState) (s16.BearersSubjectToStatusTransferItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s16.BearersSubjectToStatusTransferItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Bearers-SubjectToStatusTransfer-ItemExtIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemExtIEsValueExtensionTableCodec(table s00.BearersSubjectToStatusTransferItemExtIEsValueExtensionTable, bounds aper.ListBounds) s16.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemExtIEsValueExtensionTableFieldBound(&table) {
		return s16.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s16.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec {
		sealed := s16.BearersSubjectToStatusTransferItemExtIEsExtContainerValueCodec{}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldPath(&sealed) = "BearersSubjectToStatusTransferItemExtIEsExtContainer"
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s16.BearersSubjectToStatusTransferItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s16.BearersSubjectToStatusTransferItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, options aper.DecodeState) (s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{Bearers-SubjectToDLDiscarding-ItemIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemIEValueIEFieldTableCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s17.BearersSubjectToDLDiscardingItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemIEValueIETableFieldBound(&table) {
		return s17.BearersSubjectToDLDiscardingItemIEFieldValueCodec{}
	}
	return func() s17.BearersSubjectToDLDiscardingItemIEFieldValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingItemIEFieldValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemIEField"
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEField, error) {
			var field s17.BearersSubjectToDLDiscardingItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEField")
			}
			return field, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldEncode(&sealed) = func(field s17.BearersSubjectToDLDiscardingItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEField, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemIEValueIEFieldTableCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s17.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemIEValueIETableFieldBound(&table) {
		return s17.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec{}
	}
	return func() s17.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferItemIEFieldValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemIEField"
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEField, error) {
			var field s17.BearersSubjectToEarlyStatusTransferItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEField")
			}
			return field, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldEncode(&sealed) = func(field s17.BearersSubjectToEarlyStatusTransferItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEField, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{Bearers-SubjectToStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemIEValueIEFieldTableCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEFieldValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&table) {
		return BearersSubjectToStatusTransferItemIEFieldValueCodec{}
	}
	return BearersSubjectToStatusTransferItemIEFieldValueCodec{path: "BearersSubjectToStatusTransferItemIEField", decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, error) {
		var field BearersSubjectToStatusTransferItemIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEField")
		}
		return field, nil
	}, encode: func(field BearersSubjectToStatusTransferItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v BearersSubjectToStatusTransferItemIEField, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellTrafficTraceIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{CellTrafficTraceIEs}} codec of TS 36.413.
func CellTrafficTraceIEValueIEFieldTableCodec(table s00.CellTrafficTraceIEValueIETable) s20.CellTrafficTraceIEFieldValueCodec {
	if !*s00.BridgeCellTrafficTraceIEValueIETableFieldBound(&table) {
		return s20.CellTrafficTraceIEFieldValueCodec{}
	}
	return func() s20.CellTrafficTraceIEFieldValueCodec {
		sealed := s20.CellTrafficTraceIEFieldValueCodec{}
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldPath(&sealed) = "CellTrafficTraceIEField"
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellTrafficTraceIEField, error) {
			var field s20.CellTrafficTraceIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "CellTrafficTraceIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTrafficTraceIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "CellTrafficTraceIEField")
			}
			return field, nil
		}
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldEncode(&sealed) = func(field s20.CellTrafficTraceIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s20.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldCapture(&sealed) = func(v s20.CellTrafficTraceIEField, options aper.DecodeState) (s20.CellTrafficTraceIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldCompare(&sealed) = func(v s20.CellTrafficTraceIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCellTrafficTraceIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemIEValueIETableCodec constructs the ProtocolIE-Container {{Bearers-SubjectToDLDiscarding-ItemIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemIEValueIETableCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable, bounds aper.ListBounds) s17.BearersSubjectToDLDiscardingItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToDLDiscardingItemIEValueIETableFieldBound(&table) {
		return s17.BearersSubjectToDLDiscardingItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToDLDiscardingItemIEContainerValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingItemIEContainerValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemIEContainer"
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToDLDiscardingItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToDLDiscardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEContainer")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.BearersSubjectToDLDiscardingItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEContainer, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec constructs the ProtocolIE-Container {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable, bounds aper.ListBounds) s17.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToEarlyStatusTransferItemIEValueIETableFieldBound(&table) {
		return s17.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferItemIEContainerValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemIEContainer"
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToEarlyStatusTransferItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToEarlyStatusTransferItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEContainer")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s17.BearersSubjectToEarlyStatusTransferItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEContainer, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemIEValueIETableCodec constructs the ProtocolIE-Container {{Bearers-SubjectToStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemIEValueIETableCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable, bounds aper.ListBounds) BearersSubjectToStatusTransferItemIEContainerValueCodec {
	if !*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&table) {
		return BearersSubjectToStatusTransferItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return BearersSubjectToStatusTransferItemIEContainerValueCodec{path: "BearersSubjectToStatusTransferItemIEContainer", decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields BearersSubjectToStatusTransferItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field BearersSubjectToStatusTransferItemIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEContainer")
		}
		return fields, nil
	},
		encode: func(fields BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v BearersSubjectToStatusTransferItemIEContainer, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v BearersSubjectToStatusTransferItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// CellTrafficTraceIEValueIETableCodec constructs the ProtocolIE-Container {{CellTrafficTraceIEs}} codec of TS 36.413.
func CellTrafficTraceIEValueIETableCodec(table s00.CellTrafficTraceIEValueIETable, bounds aper.ListBounds) s20.CellTrafficTraceIEContainerValueCodec {
	if !*s00.BridgeCellTrafficTraceIEValueIETableFieldBound(&table) {
		return s20.CellTrafficTraceIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s20.CellTrafficTraceIEContainerValueCodec {
		sealed := s20.CellTrafficTraceIEContainerValueCodec{}
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldPath(&sealed) = "CellTrafficTraceIEContainer"
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellTrafficTraceIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.CellTrafficTraceIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.CellTrafficTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTrafficTraceIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEContainer")
			}
			return fields, nil
		}
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&sealed) = func(fields s20.CellTrafficTraceIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s20.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldCapture(&sealed) = func(v s20.CellTrafficTraceIEContainer, options aper.DecodeState) (s20.CellTrafficTraceIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldCompare(&sealed) = func(v s20.CellTrafficTraceIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{Bearers-SubjectToDLDiscarding-ItemIEs}} codec of TS 36.413.
func BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable) s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList"
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToDLDiscardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{Bearers-SubjectToEarlyStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable) s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList"
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToEarlyStatusTransferItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{Bearers-SubjectToStatusTransfer-ItemIEs}} codec of TS 36.413.
func BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable) BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec{path: "BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field BearersSubjectToStatusTransferItemIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellTrafficTraceIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{CellTrafficTraceIEs}} codec of TS 36.413.
func CellTrafficTraceIEValueProtocolErrorIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable) s20.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s20.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s20.CellTrafficTraceIEValueProtocolErrorIEContainerListValueCodec{}
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "CellTrafficTraceIEValueProtocolErrorIEContainerList"
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.CellTrafficTraceIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.CellTrafficTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTrafficTraceIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s20.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToDLDiscarding-ItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToDLDiscardingItemIEValueIETable, bounds aper.ListBounds) s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToDLDiscardingItemIEValueIETableCodec(table, bounds)
	if *s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList"
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToDLDiscardingItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToDLDiscardingItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToDLDiscardingItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToEarlyStatusTransfer-ItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToEarlyStatusTransferItemIEValueIETable, bounds aper.ListBounds) s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToEarlyStatusTransferItemIEValueIETableCodec(table, bounds)
	if *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList"
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s17.BearersSubjectToEarlyStatusTransferItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEContainerValueCodecFieldEncode(&codec))(s17.BearersSubjectToEarlyStatusTransferItemIEContainer(value), fresh, budget)
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToStatusTransfer-ItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListCodec(table s00.BearersSubjectToStatusTransferItemIEValueIETable, bounds aper.ListBounds) BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec {
	codec := BearersSubjectToStatusTransferItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec{path: "BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field BearersSubjectToStatusTransferItemIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(BearersSubjectToStatusTransferItemIEContainer(value), fresh, budget)
	}, capture: func(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, options aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// CellTrafficTraceIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {CellTrafficTraceIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func CellTrafficTraceIEValueProtocolIEContainerListCodec(table s00.CellTrafficTraceIEValueIETable, bounds aper.ListBounds) s20.CellTrafficTraceIEValueProtocolIEContainerListValueCodec {
	codec := CellTrafficTraceIEValueIETableCodec(table, bounds)
	if *s20.BridgeCellTrafficTraceIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.CellTrafficTraceIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s20.CellTrafficTraceIEValueProtocolIEContainerListValueCodec {
		sealed := s20.CellTrafficTraceIEValueProtocolIEContainerListValueCodec{}
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "CellTrafficTraceIEValueProtocolIEContainerList"
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellTrafficTraceIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.CellTrafficTraceIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.CellTrafficTraceIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "CellTrafficTraceIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "CellTrafficTraceIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.CellTrafficTraceIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeCellTrafficTraceIEContainerValueCodecFieldEncode(&codec))(s20.CellTrafficTraceIEContainer(value), fresh, budget)
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.CellTrafficTraceIEValueProtocolIEContainerList, options aper.DecodeState) (s20.CellTrafficTraceIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.CellTrafficTraceIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCellTrafficTraceIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// bearersSubjectToDLDiscardingItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToDLDiscardingItemIEValue].
type BearersSubjectToDLDiscardingItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.BearersSubjectToDLDiscardingItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.BearersSubjectToDLDiscardingItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(v *s17.BearersSubjectToDLDiscardingItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeBearersSubjectToDLDiscardingItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v), *s17.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(v *s17.BearersSubjectToDLDiscardingItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeBearersSubjectToDLDiscardingItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldReplay(v), *s17.BridgeBearersSubjectToDLDiscardingItemIEFieldFieldWithoutReplay(v))
}

// bearersSubjectToEarlyStatusTransferItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToEarlyStatusTransferItemIEValue].
type BearersSubjectToEarlyStatusTransferItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s17.BearersSubjectToEarlyStatusTransferItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s17.BearersSubjectToEarlyStatusTransferItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(v *s17.BearersSubjectToEarlyStatusTransferItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v), *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(v *s17.BearersSubjectToEarlyStatusTransferItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s17.BridgeBearersSubjectToEarlyStatusTransferItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldReplay(v), *s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldFieldWithoutReplay(v))
}

// bearersSubjectToStatusTransferItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToStatusTransferItemExtIEsValue].
type BearersSubjectToStatusTransferItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s16.BearersSubjectToStatusTransferItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s16.BearersSubjectToStatusTransferItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionField(v *s16.BearersSubjectToStatusTransferItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v), *s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionField(v *s16.BearersSubjectToStatusTransferItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s16.BridgeBearersSubjectToStatusTransferItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldReplay(v), *s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldFieldWithoutReplay(v))
}

// bearersSubjectToStatusTransferItemIEValueProtocolOpenValue is the concrete protocolOpenValue[BearersSubjectToStatusTransferItemIEValue].
type BearersSubjectToStatusTransferItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) BearersSubjectToStatusTransferItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(v *BearersSubjectToStatusTransferItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(v *BearersSubjectToStatusTransferItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// cellTrafficTraceIEValueProtocolOpenValue is the concrete protocolOpenValue[CellTrafficTraceIEValue].
type CellTrafficTraceIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.CellTrafficTraceIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.CellTrafficTraceIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(v *s20.CellTrafficTraceIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeCellTrafficTraceIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeCellTrafficTraceIEFieldFieldReplay(v), *s20.BridgeCellTrafficTraceIEFieldFieldWithoutReplay(v))
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(v *s20.CellTrafficTraceIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeCellTrafficTraceIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeCellTrafficTraceIEFieldFieldReplay(v), *s20.BridgeCellTrafficTraceIEFieldFieldWithoutReplay(v))
}

// BearersSubjectToStatusTransferItemAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItem].
type BearersSubjectToStatusTransferItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToStatusTransferItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferTransparentContainerAPERValue is the concrete APERValue[ENBStatusTransferTransparentContainer].
type ENBStatusTransferTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBStatusTransferTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferTransparentContainerAPERValue) WithoutReplay() ENBStatusTransferTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferListAPERValue is the concrete APERValue[BearersSubjectToStatusTransferList].
type BearersSubjectToStatusTransferListAPERValue struct {
	context s00.BridgeCodecContext
	Value   BearersSubjectToStatusTransferList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferListAPERValue) WithoutReplay() BearersSubjectToStatusTransferListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellActivationResponseAPERValue is the concrete APERValue[CellActivationResponse].
type CellActivationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellActivationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellActivationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellActivationResponseAPERValue) WithoutReplay() CellActivationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedMDTAPERValue is the concrete APERValue[CellBasedMDT].
type CellBasedMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellBasedMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedMDTAPERValue) WithoutReplay() CellBasedMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellBasedQMCAPERValue is the concrete APERValue[CellBasedQMC].
type CellBasedQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellBasedQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellBasedQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellBasedQMCAPERValue) WithoutReplay() CellBasedQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellTrafficTraceAPERValue is the concrete APERValue[CellTrafficTrace].
type CellTrafficTraceAPERValue struct {
	context s00.BridgeCodecContext
	Value   CellTrafficTrace

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v CellTrafficTraceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v CellTrafficTraceAPERValue) WithoutReplay() CellTrafficTraceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledAPERValue is the concrete APERValue[EmergencyAreaIDCancelled].
type EmergencyAreaIDCancelledAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDCancelled

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledAPERValue) WithoutReplay() EmergencyAreaIDCancelledAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EmergencyAreaIDCancelledItemAPERValue is the concrete APERValue[EmergencyAreaIDCancelledItem].
type EmergencyAreaIDCancelledItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   EmergencyAreaIDCancelledItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v EmergencyAreaIDCancelledItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v EmergencyAreaIDCancelledItemAPERValue) WithoutReplay() EmergencyAreaIDCancelledItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HOReportAPERValue is the concrete APERValue[HOReport].
type HOReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   HOReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HOReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HOReportAPERValue) WithoutReplay() HOReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UserLocationInformationExtIEsIEField uses the ProtocolIE-Field shape for object set UserLocationInformation-ExtIEs of TS 36.413.
type UserLocationInformationExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UserLocationInformationExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsIEField) WithoutReplay() UserLocationInformationExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UserLocationInformationExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UserLocationInformationExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UserLocationInformationExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformationExtIEsIEField{}
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
	var zero UserLocationInformationExtIEsValue

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

// UserLocationInformationExtIEsIEContainer uses the ProtocolIE-Container shape for object set UserLocationInformation-ExtIEs of TS 36.413: a list of UserLocationInformationExtIEsIEField values.
type UserLocationInformationExtIEsIEContainer []UserLocationInformationExtIEsIEField

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APERABIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APERABIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APERABIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APERABIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemIEValueERABIEContainerList].
type BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList) (BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueERABIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{Bearers-SubjectToStatusTransfer-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToStatusTransferItemIEValueERABIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APERABIEContainerList(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APERABIEContainerList(v *BearersSubjectToStatusTransferItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APERABIEContainerList(v *s20.CellTrafficTraceIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APERABIEContainerList(v *s20.CellTrafficTraceIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBStatusTransferIEValueERABIEContainerList].
type ENBStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, error)
	encode  func(ENBStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) New(value ENBStatusTransferIEValueERABIEContainerList) (ENBStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBStatusTransferIEValueERABIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEStatusTransferIEValueERABIEContainerList].
type MMEStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, error)
	encode  func(MMEStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) New(value MMEStatusTransferIEValueERABIEContainerList) (MMEStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEStatusTransferIEValueERABIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

// UserLocationInformationExtIEsExtFieldValueCodec is the concrete ValueCodec[UserLocationInformationExtIEsExtField].
type UserLocationInformationExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtField, error)
	encode  func(UserLocationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UserLocationInformationExtIEsExtField, aper.DecodeState) (UserLocationInformationExtIEsExtField, aper.Snapshot)
	compare func(UserLocationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UserLocationInformationExtIEsExtFieldValueCodec) New(value UserLocationInformationExtIEsExtField) (UserLocationInformationExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UserLocationInformationExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UserLocationInformationExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UserLocationInformationExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UserLocationInformationExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UserLocationInformationExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UserLocationInformationExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UserLocationInformationExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UserLocationInformationExtIEsExtFieldValueCodec) EncodeAPER(value UserLocationInformationExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UserLocationInformationExtIEsExtFieldValueCodec) encodeBudgetValue(value UserLocationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UserLocationInformationExtIEsExtFieldValueCodec) encodeChanged(value UserLocationInformationExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UserLocationInformationExtIEsExtContainerValueCodec is the concrete ValueCodec[UserLocationInformationExtIEsExtContainer].
type UserLocationInformationExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, error)
	encode  func(UserLocationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UserLocationInformationExtIEsExtContainer, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, aper.Snapshot)
	compare func(UserLocationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UserLocationInformationExtIEsExtContainerValueCodec) New(value UserLocationInformationExtIEsExtContainer) (UserLocationInformationExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UserLocationInformationExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UserLocationInformationExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UserLocationInformationExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UserLocationInformationExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UserLocationInformationExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UserLocationInformationExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UserLocationInformationExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UserLocationInformationExtIEsExtContainerValueCodec) EncodeAPER(value UserLocationInformationExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UserLocationInformationExtIEsExtContainerValueCodec) encodeBudgetValue(value UserLocationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UserLocationInformationExtIEsExtContainerValueCodec) encodeChanged(value UserLocationInformationExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEFieldValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemIEField].
type BearersSubjectToStatusTransferItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, error)
	encode  func(BearersSubjectToStatusTransferItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEField, aper.DecodeState) (BearersSubjectToStatusTransferItemIEField, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) New(value BearersSubjectToStatusTransferItemIEField) (BearersSubjectToStatusTransferItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEFieldValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEFieldValueCodec is the concrete ValueCodec[ENBStatusTransferIEField].
type ENBStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEField, error)
	encode  func(ENBStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEField, aper.DecodeState) (ENBStatusTransferIEField, aper.Snapshot)
	compare func(ENBStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEFieldValueCodec) New(value ENBStatusTransferIEField) (ENBStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEFieldValueCodec) EncodeAPER(value ENBStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEFieldValueCodec) encodeBudgetValue(value ENBStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEFieldValueCodec) encodeChanged(value ENBStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEFieldValueCodec is the concrete ValueCodec[MMEStatusTransferIEField].
type MMEStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEField, error)
	encode  func(MMEStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEField, aper.DecodeState) (MMEStatusTransferIEField, aper.Snapshot)
	compare func(MMEStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEFieldValueCodec) New(value MMEStatusTransferIEField) (MMEStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEFieldValueCodec) EncodeAPER(value MMEStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEFieldValueCodec) encodeBudgetValue(value MMEStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEFieldValueCodec) encodeChanged(value MMEStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainer(v *s17.BearersSubjectToDLDiscardingItemIEContainer, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainer(v *s17.BearersSubjectToDLDiscardingItemIEContainer, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainer(v *s17.BearersSubjectToEarlyStatusTransferItemIEContainer, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainer(v *s17.BearersSubjectToEarlyStatusTransferItemIEContainer, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEContainerValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemIEContainer].
type BearersSubjectToStatusTransferItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, error)
	encode  func(BearersSubjectToStatusTransferItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEContainer, aper.DecodeState) (BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) New(value BearersSubjectToStatusTransferItemIEContainer) (BearersSubjectToStatusTransferItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEContainerValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainer(v *BearersSubjectToStatusTransferItemIEContainer, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainer(v *BearersSubjectToStatusTransferItemIEContainer, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEContainerValueCodec is the concrete ValueCodec[ENBStatusTransferIEContainer].
type ENBStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEContainer, error)
	encode  func(ENBStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEContainer, aper.DecodeState) (ENBStatusTransferIEContainer, aper.Snapshot)
	compare func(ENBStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEContainerValueCodec) New(value ENBStatusTransferIEContainer) (ENBStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEContainerValueCodec) EncodeAPER(value ENBStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEContainerValueCodec) encodeBudgetValue(value ENBStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEContainerValueCodec) encodeChanged(value ENBStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEContainerValueCodec is the concrete ValueCodec[MMEStatusTransferIEContainer].
type MMEStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEContainer, error)
	encode  func(MMEStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEContainer, aper.DecodeState) (MMEStatusTransferIEContainer, aper.Snapshot)
	compare func(MMEStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEContainerValueCodec) New(value MMEStatusTransferIEContainer) (MMEStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEContainerValueCodec) EncodeAPER(value MMEStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEContainerValueCodec) encodeBudgetValue(value MMEStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEContainerValueCodec) encodeChanged(value MMEStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolErrorIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{Bearers-SubjectToStatusTransfer-ItemIEs}} of TS 36.413: a list of information element fields.
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolErrorIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolErrorIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolErrorIEContainerList(v *s20.CellTrafficTraceIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBStatusTransferIEValueProtocolErrorIEContainerList].
type ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBStatusTransferIEValueProtocolErrorIEContainerList) (ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBStatusTransferIEValueProtocolErrorIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEStatusTransferIEValueProtocolErrorIEContainerList].
type MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEStatusTransferIEValueProtocolErrorIEContainerList) (MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEStatusTransferIEValueProtocolErrorIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

func BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIEContainerList(v *s17.BearersSubjectToDLDiscardingItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIEContainerList(v *s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList].
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, error)
	encode  func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.DecodeState) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) New(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {Bearers-SubjectToStatusTransfer-ItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

func BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIEContainerList(v *BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainerList(v *s20.CellTrafficTraceIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainerList(v *s20.CellTrafficTraceIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBStatusTransferIEValueProtocolIEContainerList].
type ENBStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) New(value ENBStatusTransferIEValueProtocolIEContainerList) (ENBStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBStatusTransferIEValueProtocolIEContainerList []ENBStatusTransferIEValueProtocolIESingleContainer

// MMEStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEStatusTransferIEValueProtocolIEContainerList].
type MMEStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(MMEStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEStatusTransferIEValueProtocolIEContainerListValueCodec) New(value MMEStatusTransferIEValueProtocolIEContainerList) (MMEStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEStatusTransferIEValueProtocolIEContainerList []MMEStatusTransferIEValueProtocolIESingleContainer

// BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemIEValueERABIEContainerList].
type BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCellTrafficTraceIEValueCaptureS1APProtocolIESingleContainer(v *s20.CellTrafficTraceIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeCellTrafficTraceIEValueCompareS1APProtocolIESingleContainer(v *s20.CellTrafficTraceIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBStatusTransferIEValueERABIEContainerList].
type ENBStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBStatusTransferIEs}} of TS 36.413: a single information element field.
type ENBStatusTransferIEValueProtocolIESingleContainer = ENBStatusTransferIEField

// MMEStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEStatusTransferIEValueERABIEContainerList].
type MMEStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEStatusTransferIEs}} of TS 36.413: a single information element field.
type MMEStatusTransferIEValueProtocolIESingleContainer = MMEStatusTransferIEField

// UserLocationInformationExtIEsExtFieldAPERValue is the concrete APERValue[UserLocationInformationExtIEsExtField].
type UserLocationInformationExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UserLocationInformationExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UserLocationInformationExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtFieldAPERValue) WithoutReplay() UserLocationInformationExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UserLocationInformationExtIEsExtContainerAPERValue is the concrete APERValue[UserLocationInformationExtIEsExtContainer].
type UserLocationInformationExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UserLocationInformationExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UserLocationInformationExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UserLocationInformationExtIEsExtContainerAPERValue) WithoutReplay() UserLocationInformationExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEFieldAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemIEField].
type BearersSubjectToStatusTransferItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEFieldAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEFieldAPERValue is the concrete APERValue[ENBStatusTransferIEField].
type ENBStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEFieldAPERValue) WithoutReplay() ENBStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEFieldAPERValue is the concrete APERValue[MMEStatusTransferIEField].
type MMEStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEFieldAPERValue) WithoutReplay() MMEStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEContainerAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemIEContainer].
type BearersSubjectToStatusTransferItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEContainerAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEContainerAPERValue is the concrete APERValue[ENBStatusTransferIEContainer].
type ENBStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEContainerAPERValue) WithoutReplay() ENBStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEContainerAPERValue is the concrete APERValue[MMEStatusTransferIEContainer].
type MMEStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEContainerAPERValue) WithoutReplay() MMEStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList].
type BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBStatusTransferIEValueProtocolErrorIEContainerList].
type ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEStatusTransferIEValueProtocolErrorIEContainerList].
type MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList].
type BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         BearersSubjectToStatusTransferItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() BearersSubjectToStatusTransferItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBStatusTransferIEValueProtocolIEContainerList].
type ENBStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEStatusTransferIEValueProtocolIEContainerList].
type MMEStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsList(v *s16.ActivatedCellsList, s *aper.SemanticCapture) {
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
			s16.BridgeCaptureS1APActivatedCellsListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APActivatedCellsList(v *s16.ActivatedCellsList, s *aper.SemanticComparison) {
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
			s16.BridgeCompareS1APActivatedCellsListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingList(v *s17.BearersSubjectToDLDiscardingList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingList(v *s17.BearersSubjectToDLDiscardingList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToDLDiscardingItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(v *s17.BearersSubjectToEarlyStatusTransferList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(v *s17.BearersSubjectToEarlyStatusTransferList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToEarlyStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APERABID(&v.ERABID, s)
	s16.BridgeCaptureS1APCOUNTvalue(&v.ULCOUNTvalue, s)
	s16.BridgeCaptureS1APCOUNTvalue(&v.DLCOUNTvalue, s)
	{
		f := s.Begin()
		s.Bool(v.ReceiveStatusofULPDCPSDUs == nil)
		if v.ReceiveStatusofULPDCPSDUs != nil {
			s00.BridgeCaptureS1APReceiveStatusofULPDCPSDUs(v.ReceiveStatusofULPDCPSDUs, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeBearersSubjectToStatusTransferItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APERABID(&v.ERABID, s)
	s16.BridgeCompareS1APCOUNTvalue(&v.ULCOUNTvalue, s)
	s16.BridgeCompareS1APCOUNTvalue(&v.DLCOUNTvalue, s)
	{
		f := s.Begin()
		s.Bool(v.ReceiveStatusofULPDCPSDUs == nil)
		if v.ReceiveStatusofULPDCPSDUs != nil {
			s08.BridgeCompareS1APReceiveStatusofULPDCPSDUs(v.ReceiveStatusofULPDCPSDUs, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeBearersSubjectToStatusTransferItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferItemIEValue(v *BearersSubjectToStatusTransferItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(89):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToStatusTransferItem == nil)
				if v.rowBearersSubjectToStatusTransferItem != nil {
					BridgeCaptureS1APBearersSubjectToStatusTransferItem(v.rowBearersSubjectToStatusTransferItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemIEValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToStatusTransferItemIEValue {
	BridgeCaptureS1APBearersSubjectToStatusTransferItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToStatusTransferItemIEValue(v *BearersSubjectToStatusTransferItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(89):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToStatusTransferItem == nil)
				if v.rowBearersSubjectToStatusTransferItem != nil {
					BridgeCompareS1APBearersSubjectToStatusTransferItem(v.rowBearersSubjectToStatusTransferItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToStatusTransferItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToStatusTransferItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APBearersSubjectToStatusTransferList(v *BearersSubjectToStatusTransferList, s *aper.SemanticCapture) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APBearersSubjectToStatusTransferList(v *BearersSubjectToStatusTransferList, s *aper.SemanticComparison) {
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
			BridgeBearersSubjectToStatusTransferItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCNTypeRestrictions(v *s16.CNTypeRestrictions, s *aper.SemanticCapture) {
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
			s16.BridgeCaptureS1APCNTypeRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCNTypeRestrictions(v *s16.CNTypeRestrictions, s *aper.SemanticComparison) {
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
			s16.BridgeCompareS1APCNTypeRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCSGIdList(v *s17.CSGIdList, s *aper.SemanticCapture) {
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
			s17.BridgeCaptureS1APCSGIdListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCSGIdList(v *s17.CSGIdList, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCSGIdListItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCancelledCellinEAI(v *s20.CancelledCellinEAI, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCancelledCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCancelledCellinEAI(v *s20.CancelledCellinEAI, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCancelledCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCancelledCellinTAI(v *s20.CancelledCellinTAI, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCancelledCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCancelledCellinTAI(v *s20.CancelledCellinTAI, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCancelledCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCandidateCellList(v *s21.CandidateCellList, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCandidateCellList(v *s21.CandidateCellList, s *aper.SemanticComparison) {
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
func BridgeCaptureS1APCandidatePCIList(v *s17.CandidatePCIList, s *aper.SemanticCapture) {
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
			s17.BridgeCaptureS1APCandidatePCI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCandidatePCIList(v *s17.CandidatePCIList, s *aper.SemanticComparison) {
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
			s17.BridgeCompareS1APCandidatePCI(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APActivatedCellsList(&v.ActivatedCellsList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APActivatedCellsList(&v.ActivatedCellsList, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellBasedMDT(v *CellBasedMDT, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APCellIdListforMDT(&v.CellIdListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellBasedMDTExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellBasedMDT(v *CellBasedMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellIdListforMDT(&v.CellIdListforMDT, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellBasedMDTExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellBasedQMC(v *CellBasedQMC, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APCellIdListforQMC(&v.CellIdListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellBasedQMCExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellBasedQMC(v *CellBasedQMC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APCellIdListforQMC(&v.CellIdListforQMC, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeCellBasedQMCExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDBroadcast(v *s20.CellIDBroadcast, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCellIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCellIDBroadcast(v *s20.CellIDBroadcast, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCellIDBroadcastItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCellIDCancelled(v *s20.CellIDCancelled, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCellIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCellIDCancelled(v *s20.CellIDCancelled, s *aper.SemanticComparison) {
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
			s20.BridgeCompareS1APCellIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCellIdListforMDT(v *s20.CellIdListforMDT, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCellIdListforMDT(v *s20.CellIdListforMDT, s *aper.SemanticComparison) {
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
func BridgeCaptureS1APCellIdListforQMC(v *s20.CellIdListforQMC, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APCellIdListforQMC(v *s20.CellIdListforQMC, s *aper.SemanticComparison) {
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
func BridgeCaptureS1APCellTrafficTrace(v *CellTrafficTrace, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellTrafficTrace(v *CellTrafficTrace, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCellTrafficTraceIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellsToActivateList(v *s17.CellsToActivateList, s *aper.SemanticCapture) {
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
			s17.BridgeCaptureS1APCellsToActivateListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCompletedCellinEAI(v *s20.CompletedCellinEAI, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCompletedCellinEAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCompletedCellinTAI(v *s20.CompletedCellinTAI, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APCompletedCellinTAIItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APCriticalityDiagnosticsIEList(v *s17.CriticalityDiagnosticsIEList, s *aper.SemanticCapture) {
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
			s17.BridgeCaptureS1APCriticalityDiagnosticsIEItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APECGIList(v *s20.ECGIList, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APECGIListForRestart(v *s20.ECGIListForRestart, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APENBStatusTransferIEValue(v *ENBStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBStatusTransferIEValue {
	BridgeCaptureS1APENBStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBStatusTransferIEValue(v *ENBStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBStatusTransferTransparentContainer(v *ENBStatusTransferTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeENBStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBStatusTransferTransparentContainer(v *ENBStatusTransferTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeENBStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBX2ExtTLAs(v *s18.ENBX2ExtTLAs, s *aper.SemanticCapture) {
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
			s18.BridgeCaptureS1APENBX2ExtTLA(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APEmergencyAreaIDCancelled(v *EmergencyAreaIDCancelled, s *aper.SemanticCapture) {
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
			BridgeCaptureS1APEmergencyAreaIDCancelledItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APEmergencyAreaIDCancelledItem(v *EmergencyAreaIDCancelledItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	BridgeCaptureS1APCancelledCellinEAI(&v.CancelledCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEmergencyAreaIDCancelledItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEmergencyAreaIDCancelledItem(v *EmergencyAreaIDCancelledItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEmergencyAreaID(&v.EmergencyAreaID, s)
	BridgeCompareS1APCancelledCellinEAI(&v.CancelledCellinEAI, s)
	s.Bool(v.IEExtensions == nil)
	s15.BridgeEmergencyAreaIDCancelledItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APForbiddenLAs(v *s21.ForbiddenLAs, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APForbiddenLAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APForbiddenTAs(v *s21.ForbiddenTAs, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APForbiddenTAsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APGUMMEIList(v *s21.GUMMEIList, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APGUMMEI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APHOReport(v *HOReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APHoType(&v.HoType, s)
	s00.BridgeCaptureS1APHoReportType(&v.HoReportType, s)
	s21.BridgeCaptureS1APIRATCellID(&v.HosourceID, s)
	s21.BridgeCaptureS1APIRATCellID(&v.HoTargetID, s)
	BridgeCaptureS1APCandidateCellList(&v.CandidateCellList, s)
	s.Bool(v.CandidatePCIList == nil)
	BridgeCaptureS1APCandidatePCIList(&v.CandidatePCIList, s)
	s.ExtensionData(v.extData, v.extWire, 1)
	s.End(f, &v.replay, v.withoutReplay)
	if (v.CandidatePCIList != nil) && len(v.extWire) > 0 {
		s.CheckReceived(v.replay, v.extWire[0])
	}
}
func BridgeCompareS1APHOReport(v *HOReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APHoType(&v.HoType, s)
	s02.BridgeCompareS1APHoReportType(&v.HoReportType, s)
	s21.BridgeCompareS1APIRATCellID(&v.HosourceID, s)
	s21.BridgeCompareS1APIRATCellID(&v.HoTargetID, s)
	BridgeCompareS1APCandidateCellList(&v.CandidateCellList, s)
	s.Bool(v.CandidatePCIList == nil)
	BridgeCompareS1APCandidatePCIList(&v.CandidatePCIList, s)
	s.ExtensionData(v.extData, v.extWire, 1)
	s.End(f, v.replay, v.withoutReplay)
	if (v.CandidatePCIList != nil) && len(v.extWire) > 0 {
		s.CheckReceived(v.replay, v.extWire[0])
	}
}
func BridgeCaptureS1APIEsECGIList(v *s21.IEsECGIList, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APInterSystemMeasurementList(v *s21.InterSystemMeasurementList, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APInterSystemMeasurementItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APLastVisitedPSCellList(v *s23.LastVisitedPSCellList, s *aper.SemanticCapture) {
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
			s23.BridgeCaptureS1APLastVisitedPSCellInformation(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APMBSFNResultToLog(v *s22.MBSFNResultToLog, s *aper.SemanticCapture) {
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
			s22.BridgeCaptureS1APMBSFNResultToLogInfo(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APMMEStatusTransferIEValue(v *MMEStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEStatusTransferIEValue {
	BridgeCaptureS1APMMEStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEStatusTransferIEValue(v *MMEStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(90):
			{
				f := s.Begin()
				s.Bool(v.rowENBStatusTransferTransparentContainer == nil)
				if v.rowENBStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBStatusTransferTransparentContainer(v.rowENBStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APMultiCellLoadReportingResponse(v *s22.MultiCellLoadReportingResponse, s *aper.SemanticCapture) {
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
			s22.BridgeCaptureS1APMultiCellLoadReportingResponseItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APNotificationCellList(v *s23.NotificationCellList, s *aper.SemanticCapture) {
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
			s23.BridgeCaptureS1APNotificationCellListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APPC5QoSFlowList(v *s23.PC5QoSFlowList, s *aper.SemanticCapture) {
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
			s23.BridgeCaptureS1APPC5QoSFlowItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APPWSfailedECGIList(v *s23.PWSfailedECGIList, s *aper.SemanticCapture) {
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
			s20.BridgeCaptureS1APEUTRANCGI(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APRATRestrictions(v *s23.RATRestrictions, s *aper.SemanticCapture) {
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
			s23.BridgeCaptureS1APRATRestrictionsItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APReportingCellList(v *s23.ReportingCellList, s *aper.SemanticCapture) {
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
			s23.BridgeCaptureS1APReportingCellListItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APRequestedCellList(v *s23.RequestedCellList, s *aper.SemanticCapture) {
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
			s21.BridgeCaptureS1APIRATCellID(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureS1APUserLocationInformationExtIEsValue(v *UserLocationInformationExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s23.BridgeCaptureS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s22.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UserLocationInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) UserLocationInformationExtIEsValue {
	BridgeCaptureS1APUserLocationInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APUserLocationInformationExtIEsValue(v *UserLocationInformationExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s23.BridgeCompareS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s22.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UserLocationInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUserLocationInformationExtIEsValue(&v, &s)
	return s
}

type BearersSubjectToStatusTransferList = []BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer

// BearersSubjectToStatusTransferItem represents the ASN.1 type Bearers-SubjectToStatusTransfer-Item (SEQUENCE).
type BearersSubjectToStatusTransferItem struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	ERABID                    s00.ERABID                                               `asn1:"tag:0,context,implicit"`
	ULCOUNTvalue              s16.COUNTvalue                                           `asn1:"tag:1,context,implicit"`
	DLCOUNTvalue              s16.COUNTvalue                                           `asn1:"tag:2,context,implicit"`
	ReceiveStatusofULPDCPSDUs *s00.ReceiveStatusofULPDCPSDUs                           `asn1:"tag:3,context,implicit,optional" json:"ReceiveStatusofULPDCPSDUs,omitempty"`
	IEExtensions              s16.BearersSubjectToStatusTransferItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                     `asn1:"-" json:"-"`
	extCount                  int64                                                    `asn1:"-" json:"-"`
	extPresent                []bool                                                   `asn1:"-" json:"-"`
	extData                   [][]byte                                                 `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                        `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                   `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// CellBasedMDT represents the ASN.1 type CellBasedMDT (SEQUENCE).
type CellBasedMDT struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	CellIdListforMDT      s20.CellIdListforMDT               `asn1:"tag:0,context,implicit"`
	cellIdListforMDTIndef bool                               `asn1:"-" json:"-"`
	IEExtensions          s08.CellBasedMDTExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                               `asn1:"-" json:"-"`
	extCount              int64                              `asn1:"-" json:"-"`
	extPresent            []bool                             `asn1:"-" json:"-"`
	extData               [][]byte                           `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// CellBasedQMC represents the ASN.1 type CellBasedQMC (SEQUENCE).
type CellBasedQMC struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	CellIdListforQMC      s20.CellIdListforQMC               `asn1:"tag:0,context,implicit"`
	cellIdListforQMCIndef bool                               `asn1:"-" json:"-"`
	IEExtensions          s08.CellBasedQMCExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                               `asn1:"-" json:"-"`
	extCount              int64                              `asn1:"-" json:"-"`
	extPresent            []bool                             `asn1:"-" json:"-"`
	extData               [][]byte                           `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}
type EmergencyAreaIDCancelled = []EmergencyAreaIDCancelledItem

// EmergencyAreaIDCancelledItem represents the ASN.1 type EmergencyAreaID-Cancelled-Item (SEQUENCE).
type EmergencyAreaIDCancelledItem struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	EmergencyAreaID         s00.EmergencyAreaID                                `asn1:"tag:0,context,implicit"`
	CancelledCellinEAI      s20.CancelledCellinEAI                             `asn1:"tag:1,context,implicit"`
	cancelledCellinEAIIndef bool                                               `asn1:"-" json:"-"`
	IEExtensions            s10.EmergencyAreaIDCancelledItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                               `asn1:"-" json:"-"`
	extCount                int64                                              `asn1:"-" json:"-"`
	extPresent              []bool                                             `asn1:"-" json:"-"`
	extData                 [][]byte                                           `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// ENBStatusTransferTransparentContainer represents the ASN.1 type ENB-StatusTransfer-TransparentContainer (SEQUENCE).
type ENBStatusTransferTransparentContainer struct {
	replay                                  aper.Snapshot
	stream                                  aper.WireSpan
	received                                bool
	withoutReplay                           bool
	receivedAbsolute                        bool
	receivedBytes                           aper.WireSpan
	receivedLocation                        aper.Location
	BearersSubjectToStatusTransferList      BearersSubjectToStatusTransferList                          `asn1:"tag:0,context,implicit"`
	bearersSubjectToStatusTransferListIndef bool                                                        `asn1:"-" json:"-"`
	IEExtensions                            s09.ENBStatusTransferTransparentContainerExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                       bool                                                        `asn1:"-" json:"-"`
	extCount                                int64                                                       `asn1:"-" json:"-"`
	extPresent                              []bool                                                      `asn1:"-" json:"-"`
	extData                                 [][]byte                                                    `asn1:"-" json:"-"`
	perPadding                              aper.FinalPadding                                           `asn1:"-" json:"-"`
	perExtPadding                           []aper.CompletePadding                                      `asn1:"-" json:"-"`
	extOrigin                               []aper.OpaqueOrigin
	extWire                                 []aper.WireSpan
}
type BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue struct {
	Value BearersSubjectToStatusTransferList
}

// MarshalAPER encodes BearersSubjectToStatusTransferItem to APER format.
func (v *BearersSubjectToStatusTransferItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ReceiveStatusofULPDCPSDUs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ERABID, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
		return fmt.Errorf("encoding e-RAB-ID: %w", err)
	}
	if err := s16.BridgeCOUNTvalueMethodMarshalAPERTo(&v.ULCOUNTvalue, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding uL-COUNTvalue: %w", err)
	}
	if err := s16.BridgeCOUNTvalueMethodMarshalAPERTo(&v.DLCOUNTvalue, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding dL-COUNTvalue: %w", err)
	}
	if v.ReceiveStatusofULPDCPSDUs != nil {
		if err := aper.EncodeBitStringAligned(bb, v.ReceiveStatusofULPDCPSDUs.Bytes, v.ReceiveStatusofULPDCPSDUs.BitLength, 4096, 4096, true); err != nil {
			return fmt.Errorf("encoding receiveStatusofULPDCPSDUs: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes BearersSubjectToStatusTransferItem from APER format.
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	bb.EnterComponent("BearersSubjectToStatusTransferItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
	}
	v.perPadding = padding
	return nil
}
func (v *BearersSubjectToStatusTransferItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = BearersSubjectToStatusTransferItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_receivestatusofulpdcpsdus, err := aper.DecodeBoolean(bb)
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
	toleranceMark_ulcountvalue := bb.EnterComponent("ULCOUNTvalue")
	if err := s16.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&v.ULCOUNTvalue, bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCOUNTvalue")
	}
	bb.LeaveComponent(toleranceMark_ulcountvalue)
	toleranceMark_dlcountvalue := bb.EnterComponent("DLCOUNTvalue")
	if err := s16.BridgeCOUNTvalueMethodUnmarshalAPERFrom(&v.DLCOUNTvalue, bb); err != nil {
		return runtime.WrapDecodePath(err, "DLCOUNTvalue")
	}
	bb.LeaveComponent(toleranceMark_dlcountvalue)
	if opt_receivestatusofulpdcpsdus {
		bsBytes_receivestatusofulpdcpsdus, bsBitLen_receivestatusofulpdcpsdus, err := aper.DecodeBitStringAligned(bb, 4096, 4096, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "ReceiveStatusofULPDCPSDUs")
		}
		tmp_receivestatusofulpdcpsdus := runtime.BitString{Bytes: bsBytes_receivestatusofulpdcpsdus, BitLength: bsBitLen_receivestatusofulpdcpsdus}
		if err := aper.ChargeValue(bb, tmp_receivestatusofulpdcpsdus); err != nil {
			return err
		}
		v.ReceiveStatusofULPDCPSDUs = &tmp_receivestatusofulpdcpsdus
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s16.BearersSubjectToStatusTransferItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s16.BearersSubjectToStatusTransferItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s16.BridgeBearersSubjectToStatusTransferItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue struct {
	Value s17.BearersSubjectToEarlyStatusTransferList
}
type BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue struct {
	Value s17.BearersSubjectToDLDiscardingList
}
type BridgeAsn1cAPERCancelledCellinEAIListValue struct{ Value s20.CancelledCellinEAI }
type BridgeAsn1cAPERCancelledCellinTAIListValue struct{ Value s20.CancelledCellinTAI }
type BridgeAsn1cAPERCellIDBroadcastListValue struct{ Value s20.CellIDBroadcast }
type BridgeAsn1cAPERCellIDCancelledListValue struct{ Value s20.CellIDCancelled }

// MarshalAPER encodes CellBasedMDT to APER format.
func (v *CellBasedMDT) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellBasedMDT) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.CellIdListforMDT)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistformdt, fragmentLength_cellidlistformdt int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellidlistformdt < 0 || fragmentOffset_cellidlistformdt > int64(len(v.CellIdListforMDT)) || fragmentLength_cellidlistformdt < 0 || fragmentLength_cellidlistformdt > int64(len(v.CellIdListforMDT[fragmentOffset_cellidlistformdt:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellIdListforMDT[fragmentOffset_cellidlistformdt : fragmentOffset_cellidlistformdt+fragmentLength_cellidlistformdt] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellIdListforMDT element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellIdListforMDT: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellBasedMDT from APER format.
func (v *CellBasedMDT) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellBasedMDT) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	bb.EnterComponent("CellBasedMDT")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellBasedMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellBasedMDT")
	}
	v.perPadding = padding
	return nil
}
func (v *CellBasedMDT) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedMDT{}
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
	toleranceMark_cellidlistformdt := bb.EnterComponent("CellIdListforMDT")
	v.CellIdListforMDT = make(s20.CellIdListforMDT, 0)
	_, errCollection_cellidlistformdt := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistformdt, fragmentLength_cellidlistformdt int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_cellidlistformdt < 0 || fragmentLength_cellidlistformdt < 0 || fragmentLength_cellidlistformdt > int64(^uint(0)>>1) || fragmentOffset_cellidlistformdt > int64(^uint(0)>>1)-fragmentLength_cellidlistformdt {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellidlistformdt; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_cellidlistformdt + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdListforMDT[%d]", fragmentOffset_cellidlistformdt+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CellIdListforMDT, elem); err != nil {
				return err
			} else {
				v.CellIdListforMDT = next
			}
		}
		return nil
	})
	if errCollection_cellidlistformdt != nil {
		return runtime.WrapDecodePath(errCollection_cellidlistformdt, "CellIdListforMDT")
	}
	bb.LeaveComponent(toleranceMark_cellidlistformdt)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CellBasedMDTExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CellBasedMDTExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCellBasedMDTExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERCellIdListforMDTListValue struct{ Value s20.CellIdListforMDT }

// MarshalAPER encodes CellBasedQMC to APER format.
func (v *CellBasedQMC) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellBasedQMC) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.CellIdListforQMC)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistforqmc, fragmentLength_cellidlistforqmc int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cellidlistforqmc < 0 || fragmentOffset_cellidlistforqmc > int64(len(v.CellIdListforQMC)) || fragmentLength_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc > int64(len(v.CellIdListforQMC[fragmentOffset_cellidlistforqmc:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CellIdListforQMC[fragmentOffset_cellidlistforqmc : fragmentOffset_cellidlistforqmc+fragmentLength_cellidlistforqmc] {
			if err := s20.BridgeEUTRANCGIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cellIdListforQMC element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cellIdListforQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellBasedQMC from APER format.
func (v *CellBasedQMC) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellBasedQMC) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	bb.EnterComponent("CellBasedQMC")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellBasedQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellBasedQMC")
	}
	v.perPadding = padding
	return nil
}
func (v *CellBasedQMC) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellBasedQMC{}
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
	toleranceMark_cellidlistforqmc := bb.EnterComponent("CellIdListforQMC")
	v.CellIdListforQMC = make(s20.CellIdListforQMC, 0)
	_, errCollection_cellidlistforqmc := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_cellidlistforqmc, fragmentLength_cellidlistforqmc int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc < 0 || fragmentLength_cellidlistforqmc > int64(^uint(0)>>1) || fragmentOffset_cellidlistforqmc > int64(^uint(0)>>1)-fragmentLength_cellidlistforqmc {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cellidlistforqmc; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_cellidlistforqmc + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CellIdListforQMC[%d]", fragmentOffset_cellidlistforqmc+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CellIdListforQMC, elem); err != nil {
				return err
			} else {
				v.CellIdListforQMC = next
			}
		}
		return nil
	})
	if errCollection_cellidlistforqmc != nil {
		return runtime.WrapDecodePath(errCollection_cellidlistforqmc, "CellIdListforQMC")
	}
	bb.LeaveComponent(toleranceMark_cellidlistforqmc)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.CellBasedQMCExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.CellBasedQMCExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeCellBasedQMCExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERCellIdListforQMCListValue struct{ Value s20.CellIdListforQMC }
type BridgeAsn1cAPERCNTypeRestrictionsListValue struct{ Value s16.CNTypeRestrictions }
type BridgeAsn1cAPERCSGIdListListValue struct{ Value s17.CSGIdList }
type BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue struct {
	Value s17.CriticalityDiagnosticsIEList
}
type BridgeAsn1cAPERDAPSResponseInfoListListValue struct{ Value s17.DAPSResponseInfoList }
type BridgeAsn1cAPERECGIListListValue struct{ Value s20.ECGIList }
type BridgeAsn1cAPERPWSfailedECGIListListValue struct{ Value s23.PWSfailedECGIList }
type BridgeAsn1cAPEREmergencyAreaIDCancelledListValue struct{ Value EmergencyAreaIDCancelled }

// MarshalAPER encodes EmergencyAreaIDCancelledItem to APER format.
func (v *EmergencyAreaIDCancelledItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.EmergencyAreaID), 3, 3, true); err != nil {
		return fmt.Errorf("encoding emergencyAreaID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CancelledCellinEAI)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellineai, fragmentLength_cancelledcellineai int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_cancelledcellineai < 0 || fragmentOffset_cancelledcellineai > int64(len(v.CancelledCellinEAI)) || fragmentLength_cancelledcellineai < 0 || fragmentLength_cancelledcellineai > int64(len(v.CancelledCellinEAI[fragmentOffset_cancelledcellineai:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CancelledCellinEAI[fragmentOffset_cancelledcellineai : fragmentOffset_cancelledcellineai+fragmentLength_cancelledcellineai] {
			if err := s20.BridgeCancelledCellinEAIItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding cancelledCellinEAI element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding cancelledCellinEAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes EmergencyAreaIDCancelledItem from APER format.
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	bb.EnterComponent("EmergencyAreaIDCancelledItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "EmergencyAreaIDCancelledItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaIDCancelledItem")
	}
	v.perPadding = padding
	return nil
}
func (v *EmergencyAreaIDCancelledItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EmergencyAreaIDCancelledItem{}
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
	val_emergencyareaid, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EmergencyAreaID")
	}
	v.EmergencyAreaID = s00.EmergencyAreaID(val_emergencyareaid)
	toleranceMark_cancelledcellineai := bb.EnterComponent("CancelledCellinEAI")
	v.CancelledCellinEAI = make(s20.CancelledCellinEAI, 0)
	_, errCollection_cancelledcellineai := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_cancelledcellineai, fragmentLength_cancelledcellineai int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_cancelledcellineai < 0 || fragmentLength_cancelledcellineai < 0 || fragmentLength_cancelledcellineai > int64(^uint(0)>>1) || fragmentOffset_cancelledcellineai > int64(^uint(0)>>1)-fragmentLength_cancelledcellineai {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_cancelledcellineai; i++ {
			var elem s20.CancelledCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_cancelledcellineai + i)
			if err := s20.BridgeCancelledCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CancelledCellinEAI[%d]", fragmentOffset_cancelledcellineai+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CancelledCellinEAI, elem); err != nil {
				return err
			} else {
				v.CancelledCellinEAI = next
			}
		}
		return nil
	})
	if errCollection_cancelledcellineai != nil {
		return runtime.WrapDecodePath(errCollection_cancelledcellineai, "CancelledCellinEAI")
	}
	bb.LeaveComponent(toleranceMark_cancelledcellineai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.EmergencyAreaIDCancelledItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.EmergencyAreaIDCancelledItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeEmergencyAreaIDCancelledItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERCompletedCellinEAIListValue struct{ Value s20.CompletedCellinEAI }
type BridgeAsn1cAPERIEsECGIListListValue struct{ Value s21.IEsECGIList }
type BridgeAsn1cAPERGUMMEIListListValue struct{ Value s21.GUMMEIList }

// MarshalAPER encodes ENBStatusTransferTransparentContainer to APER format.
func (v *ENBStatusTransferTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.BearersSubjectToStatusTransferList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttostatustransferlist, fragmentLength_bearerssubjecttostatustransferlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bearerssubjecttostatustransferlist < 0 || fragmentOffset_bearerssubjecttostatustransferlist > int64(len(v.BearersSubjectToStatusTransferList)) || fragmentLength_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist > int64(len(v.BearersSubjectToStatusTransferList[fragmentOffset_bearerssubjecttostatustransferlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BearersSubjectToStatusTransferList[fragmentOffset_bearerssubjecttostatustransferlist : fragmentOffset_bearerssubjecttostatustransferlist+fragmentLength_bearerssubjecttostatustransferlist] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding bearers-SubjectToStatusTransferList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bearers-SubjectToStatusTransferList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBStatusTransferTransparentContainer from APER format.
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	bb.EnterComponent("ENBStatusTransferTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBStatusTransferTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
	}
	v.perPadding = padding
	return nil
}
func (v *ENBStatusTransferTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBStatusTransferTransparentContainer{}
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
	toleranceMark_bearerssubjecttostatustransferlist := bb.EnterComponent("BearersSubjectToStatusTransferList")
	v.BearersSubjectToStatusTransferList = make(BearersSubjectToStatusTransferList, 0)
	_, errCollection_bearerssubjecttostatustransferlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttostatustransferlist, fragmentLength_bearerssubjecttostatustransferlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist < 0 || fragmentLength_bearerssubjecttostatustransferlist > int64(^uint(0)>>1) || fragmentOffset_bearerssubjecttostatustransferlist > int64(^uint(0)>>1)-fragmentLength_bearerssubjecttostatustransferlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bearerssubjecttostatustransferlist; i++ {
			var elem BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_bearerssubjecttostatustransferlist + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferList[%d]", fragmentOffset_bearerssubjecttostatustransferlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.BearersSubjectToStatusTransferList, elem); err != nil {
				return err
			} else {
				v.BearersSubjectToStatusTransferList = next
			}
		}
		return nil
	})
	if errCollection_bearerssubjecttostatustransferlist != nil {
		return runtime.WrapDecodePath(errCollection_bearerssubjecttostatustransferlist, "BearersSubjectToStatusTransferList")
	}
	bb.LeaveComponent(toleranceMark_bearerssubjecttostatustransferlist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.ENBStatusTransferTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ENBStatusTransferTransparentContainerExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeENBStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABListListValue struct{ Value s19.ERABList }
type BridgeAsn1cAPERERABUsageReportListListValue struct{ Value s20.ERABUsageReportList }
type BridgeAsn1cAPERForbiddenTAsListValue struct{ Value s21.ForbiddenTAs }
type BridgeAsn1cAPERForbiddenLAsListValue struct{ Value s21.ForbiddenLAs }
type BridgeAsn1cAPERInterSystemMeasurementListListValue struct {
	Value s21.InterSystemMeasurementList
}
type BridgeAsn1cAPERLastVisitedPSCellListListValue struct{ Value s23.LastVisitedPSCellList }
type BridgeAsn1cAPERMBSFNResultToLogListValue struct{ Value s22.MBSFNResultToLog }
type BridgeAsn1cAPERPC5QoSFlowListListValue struct{ Value s23.PC5QoSFlowList }
type BridgeAsn1cAPERRATRestrictionsListValue struct{ Value s23.RATRestrictions }
type BridgeAsn1cAPERECGIListForRestartListValue struct{ Value s20.ECGIListForRestart }
type BridgeAsn1cAPERCompletedCellinTAIListValue struct{ Value s20.CompletedCellinTAI }
type BridgeAsn1cAPERENBX2ExtTLAsListValue struct{ Value s18.ENBX2ExtTLAs }

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToStatusTransferItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToStatusTransferItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToStatusTransferItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToStatusTransferItem) WithoutReplay() BearersSubjectToStatusTransferItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToStatusTransferItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellBasedMDT) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellBasedMDT", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellBasedMDT", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellBasedMDT) WithoutReplay() CellBasedMDT {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellBasedMDT
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellBasedQMC) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellBasedQMC", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellBasedQMC", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellBasedQMC) WithoutReplay() CellBasedQMC {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellBasedQMC
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBStatusTransferTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBStatusTransferTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBStatusTransferTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBStatusTransferTransparentContainer) WithoutReplay() ENBStatusTransferTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBStatusTransferTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EmergencyAreaIDCancelledItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EmergencyAreaIDCancelledItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EmergencyAreaIDCancelledItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EmergencyAreaIDCancelledItem) WithoutReplay() EmergencyAreaIDCancelledItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EmergencyAreaIDCancelledItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *BearersSubjectToStatusTransferItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *BearersSubjectToStatusTransferItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *BearersSubjectToStatusTransferItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToStatusTransferItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellBasedMDT) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellBasedMDT) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellBasedMDT) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedMDT.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *CellBasedQMC) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellBasedQMC) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellBasedQMC) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellBasedQMC.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBStatusTransferTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBStatusTransferTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBStatusTransferTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EmergencyAreaIDCancelledItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EmergencyAreaIDCancelledItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EmergencyAreaIDCancelledItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EmergencyAreaIDCancelledItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToStatusTransferItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToStatusTransferItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToStatusTransferItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToStatusTransferItem(v, &s)
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
func (v *BearersSubjectToStatusTransferItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToStatusTransferItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellBasedMDT) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellBasedMDT")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellBasedMDT) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellBasedMDT")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellBasedMDT(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellBasedMDT")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellBasedMDT")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellBasedMDT) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellBasedMDT")
}
func (v *CellBasedMDT) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellBasedMDT")
}
func (v *CellBasedMDT) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellBasedMDT(v, &s)
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
func (v *CellBasedMDT) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellBasedMDT) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellBasedQMC) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellBasedQMC")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellBasedQMC) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellBasedQMC")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellBasedQMC(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellBasedQMC")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellBasedQMC")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellBasedQMC) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellBasedQMC")
}
func (v *CellBasedQMC) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellBasedQMC")
}
func (v *CellBasedQMC) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellBasedQMC(v, &s)
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
func (v *CellBasedQMC) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellBasedQMC) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBStatusTransferTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransferTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBStatusTransferTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBStatusTransferTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBStatusTransferTransparentContainer(v, &s)
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
func (v *ENBStatusTransferTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBStatusTransferTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *EmergencyAreaIDCancelledItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEmergencyAreaIDCancelledItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EmergencyAreaIDCancelledItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEmergencyAreaIDCancelledItem(v, &s)
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
func (v *EmergencyAreaIDCancelledItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EmergencyAreaIDCancelledItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BearersSubjectToStatusTransferItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToStatusTransferItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToStatusTransferItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToStatusTransferItem{}
		return report, aper.OperationError(err, "BearersSubjectToStatusTransferItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToStatusTransferItem")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellBasedMDT) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellBasedMDT")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellBasedMDT
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellBasedMDT(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellBasedMDT{}
		return report, aper.OperationError(err, "CellBasedMDT")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellBasedMDT")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellBasedQMC) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellBasedQMC")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellBasedQMC
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellBasedQMC(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellBasedQMC{}
		return report, aper.OperationError(err, "CellBasedQMC")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellBasedQMC")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBStatusTransferTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBStatusTransferTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBStatusTransferTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBStatusTransferTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBStatusTransferTransparentContainer{}
		return report, aper.OperationError(err, "ENBStatusTransferTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBStatusTransferTransparentContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EmergencyAreaIDCancelledItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EmergencyAreaIDCancelledItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EmergencyAreaIDCancelledItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEmergencyAreaIDCancelledItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EmergencyAreaIDCancelledItem{}
		return report, aper.OperationError(err, "EmergencyAreaIDCancelledItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EmergencyAreaIDCancelledItem")
}

// CellTrafficTrace represents the ASN.1 type CellTrafficTrace (SEQUENCE).
type CellTrafficTrace struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s20.CellTrafficTraceIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type BridgeAsn1cAPERERABSubjecttoDataForwardingListListValue struct {
	Value s20.ERABSubjecttoDataForwardingList
}
type BridgeAsn1cAPERERABAdmittedListListValue struct{ Value s18.ERABAdmittedList }
type BridgeAsn1cAPERERABFailedtoSetupListHOReqAckListValue struct {
	Value s19.ERABFailedtoSetupListHOReqAck
}
type BridgeAsn1cAPERERABToBeSwitchedULListListValue struct{ Value s20.ERABToBeSwitchedULList }
type BridgeAsn1cAPERERABSetupListBearerSUResListValue struct{ Value s20.ERABSetupListBearerSURes }
type BridgeAsn1cAPERERABModifyListBearerModResListValue struct {
	Value s19.ERABModifyListBearerModRes
}
type BridgeAsn1cAPERERABReleaseListBearerRelCompListValue struct {
	Value s19.ERABReleaseListBearerRelComp
}
type BridgeAsn1cAPERERABSetupListCtxtSUResListValue struct{ Value s20.ERABSetupListCtxtSURes }

// MarshalAPER encodes CellTrafficTrace to APER format.
func (v *CellTrafficTrace) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellTrafficTrace) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s20.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes CellTrafficTrace from APER format.
func (v *CellTrafficTrace) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellTrafficTrace) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	bb.EnterComponent("CellTrafficTrace")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellTrafficTrace")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellTrafficTrace")
	}
	v.perPadding = padding
	return nil
}
func (v *CellTrafficTrace) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellTrafficTrace{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s20.CellTrafficTraceIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s20.CellTrafficTraceIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s20.BridgeCellTrafficTraceIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERERABToBeModifiedListBearerModIndListValue struct {
	Value s20.ERABToBeModifiedListBearerModInd
}
type BridgeAsn1cAPERERABNotToBeModifiedListBearerModIndListValue struct {
	Value s19.ERABNotToBeModifiedListBearerModInd
}
type BridgeAsn1cAPERERABModifyListBearerModConfListValue struct {
	Value s19.ERABModifyListBearerModConf
}
type BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue struct {
	Value s18.ERABFailedToResumeListResumeReq
}
type BridgeAsn1cAPERERABFailedToResumeListResumeResListValue struct {
	Value s18.ERABFailedToResumeListResumeRes
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellTrafficTrace) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellTrafficTrace", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellTrafficTrace", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellTrafficTrace) WithoutReplay() CellTrafficTrace {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellTrafficTrace
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellTrafficTrace) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellTrafficTrace) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellTrafficTrace) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellTrafficTrace.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellTrafficTrace) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellTrafficTrace")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellTrafficTrace) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellTrafficTrace")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellTrafficTrace(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellTrafficTrace")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellTrafficTrace")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellTrafficTrace) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellTrafficTrace")
}
func (v *CellTrafficTrace) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellTrafficTrace")
}
func (v *CellTrafficTrace) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellTrafficTrace(v, &s)
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
func (v *CellTrafficTrace) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellTrafficTrace) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellTrafficTrace) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellTrafficTrace")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellTrafficTrace
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellTrafficTrace(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellTrafficTrace{}
		return report, aper.OperationError(err, "CellTrafficTrace")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellTrafficTrace")
}

// HOReport represents the ASN.1 type HOReport (SEQUENCE).
type HOReport struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	HoType                 s00.HoType             `asn1:"tag:0,context,implicit"`
	HoReportType           s00.HoReportType       `asn1:"tag:1,context,implicit"`
	HosourceID             s21.IRATCellID         `asn1:"tag:2,context,explicit"`
	HoTargetID             s21.IRATCellID         `asn1:"tag:3,context,explicit"`
	CandidateCellList      s21.CandidateCellList  `asn1:"tag:4,context,implicit"`
	candidateCellListIndef bool                   `asn1:"-" json:"-"`
	CandidatePCIList       s17.CandidatePCIList   `asn1:"tag:5,context,implicit,optional" json:"CandidatePCIList,omitzero"`
	candidatePCIListIndef  bool                   `asn1:"-" json:"-"`
	extCount               int64                  `asn1:"-" json:"-"`
	extPresent             []bool                 `asn1:"-" json:"-"`
	extData                [][]byte               `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// CellActivationResponse represents the ASN.1 type CellActivationResponse (SEQUENCE).
type CellActivationResponse struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	ActivatedCellsList      s16.ActivatedCellsList `asn1:"tag:0,context,implicit"`
	activatedCellsListIndef bool                   `asn1:"-" json:"-"`
	extCount                int64                  `asn1:"-" json:"-"`
	extPresent              []bool                 `asn1:"-" json:"-"`
	extData                 [][]byte               `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}
type BridgeAsn1cAPERRequestedCellListListValue struct{ Value s23.RequestedCellList }
type BridgeAsn1cAPERReportingCellListListValue struct{ Value s23.ReportingCellList }
type BridgeAsn1cAPERMultiCellLoadReportingResponseListValue struct {
	Value s22.MultiCellLoadReportingResponse
}

// MarshalAPER encodes HOReport to APER format.
func (v *HOReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HOReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	hasExtensions = hasExtensions || (v.CandidatePCIList != nil)
	for i, present := range v.extPresent {
		if i >= 1 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 1 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.HoType), 2, true); err != nil {
		return fmt.Errorf("encoding hoType: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.HoReportType), 1, true); err != nil {
		return fmt.Errorf("encoding hoReportType: %w", err)
	}
	if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&v.HosourceID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding hosourceID: %w", err)
	}
	if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&v.HoTargetID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding hoTargetID: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.CandidateCellList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_candidatecelllist < 0 || fragmentOffset_candidatecelllist > int64(len(v.CandidateCellList)) || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(len(v.CandidateCellList[fragmentOffset_candidatecelllist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.CandidateCellList[fragmentOffset_candidatecelllist : fragmentOffset_candidatecelllist+fragmentLength_candidatecelllist] {
			if err := s21.BridgeIRATCellIDMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding candidateCellList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding candidateCellList: %w", err)
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.CandidatePCIList != nil {
			extHighest = 0
		}
		if extensionCount > extHighest {
			extHighest = extensionCount
		}
		for i, present := range v.extPresent {
			if present && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		for i, data := range extensionEncodingData {
			if data != nil && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extHighest+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extHighest < 16383; gen/codegen_aper.go:352
		if extHighest < 0 || extHighest >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extHighest)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extHighest+1); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := v.CandidatePCIList != nil
			if err := aper.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_1: 0 <= extHighest < max int; gen/codegen_aper.go:368
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if v.CandidatePCIList != nil {
			extBuf := aper.NewBudgetBuffer(bb.Budget())
			if v.CandidatePCIList != nil {
				if err := aper.EncodeCollection(extBuf, int64(len(v.CandidatePCIList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
					if fragmentOffset_candidatepcilist < 0 || fragmentOffset_candidatepcilist > int64(len(v.CandidatePCIList)) || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(len(v.CandidatePCIList[fragmentOffset_candidatepcilist:])) {
						return fmt.Errorf("collection fragment outside value")
					}
					for _, elem := range v.CandidatePCIList[fragmentOffset_candidatepcilist : fragmentOffset_candidatepcilist+fragmentLength_candidatepcilist] {
						if err := s17.BridgeCandidatePCIMethodMarshalAPERTo(&elem, extBuf, len(fresh) != 0 && fresh[0]); err != nil {
							return fmt.Errorf("encoding candidatePCIList element: %w", err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("encoding candidatePCIList: %w", err)
				}
			}
			var extPadding aper.CompletePadding
			if !(len(fresh) != 0 && fresh[0]) && len(v.perExtPadding) > 0 {
				extPadding = v.perExtPadding[0]
			}
			extBytes, err := extBuf.CompleteBytesWithPadding(extPadding)
			if err != nil {
				return err
			}
			if err := aper.EncodeOpenTypeAligned(bb, extBytes); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_2: 0 <= extHighest < max int; gen/codegen_aper.go:420
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
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

// UnmarshalAPER decodes HOReport from APER format.
func (v *HOReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *HOReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	bb.EnterComponent("HOReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "HOReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "HOReport")
	}
	v.perPadding = padding
	return nil
}
func (v *HOReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HOReport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_hotype, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "HoType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "HoType")
	}
	v.HoType = s00.HoType(val_hotype)
	val_horeporttype, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "HoReportType"})
	if err != nil {
		return runtime.WrapDecodePath(err, "HoReportType")
	}
	v.HoReportType = s00.HoReportType(val_horeporttype)
	toleranceMark_hosourceid := bb.EnterComponent("HosourceID")
	if err := s21.BridgeIRATCellIDMethodUnmarshalAPERFrom(&v.HosourceID, bb); err != nil {
		return runtime.WrapDecodePath(err, "HosourceID")
	}
	bb.LeaveComponent(toleranceMark_hosourceid)
	toleranceMark_hotargetid := bb.EnterComponent("HoTargetID")
	if err := s21.BridgeIRATCellIDMethodUnmarshalAPERFrom(&v.HoTargetID, bb); err != nil {
		return runtime.WrapDecodePath(err, "HoTargetID")
	}
	bb.LeaveComponent(toleranceMark_hotargetid)
	toleranceMark_candidatecelllist := bb.EnterComponent("CandidateCellList")
	v.CandidateCellList = make(s21.CandidateCellList, 0)
	_, errCollection_candidatecelllist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatecelllist, fragmentLength_candidatecelllist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_candidatecelllist < 0 || fragmentLength_candidatecelllist < 0 || fragmentLength_candidatecelllist > int64(^uint(0)>>1) || fragmentOffset_candidatecelllist > int64(^uint(0)>>1)-fragmentLength_candidatecelllist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_candidatecelllist; i++ {
			var elem s21.IRATCellID
			elementMark := bb.EnterIndex(fragmentOffset_candidatecelllist + i)
			if err := s21.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("CandidateCellList[%d]", fragmentOffset_candidatecelllist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.CandidateCellList, elem); err != nil {
				return err
			} else {
				v.CandidateCellList = next
			}
		}
		return nil
	})
	if errCollection_candidatecelllist != nil {
		return runtime.WrapDecodePath(errCollection_candidatecelllist, "CandidateCellList")
	}
	bb.LeaveComponent(toleranceMark_candidatecelllist)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_ALLOC_1: 0 <= extCount < max int; gen/codegen_aper.go:547
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_2: 0 <= extCount < max int; gen/codegen_aper.go:549
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[aper.CompletePadding](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.perExtPadding = make([]aper.CompletePadding, len(extPresent))
		if int64(0) <= extCount && extPresent[0] {
			extRaw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§19.9"})
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			extRaw.RetainContents(&v.extWire[0])
			if err := func() error {
				extBB := extRaw.ChildDecodeBuffer()
				if err := extBB.EnterOpenType(); err != nil {
					return err
				}
				defer extBB.LeaveOpenType()
				_ = extBB
				paddingMark := extBB.EnterComponent("Extensions[0]")
				toleranceMark_candidatepcilist := extBB.EnterComponent("CandidatePCIList")
				tmp_candidatepcilist := make(s17.CandidatePCIList, 0)
				_, errCollection_candidatepcilist := aper.DecodeCollection(extBB, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_candidatepcilist, fragmentLength_candidatepcilist int64) error {
					// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
					if fragmentOffset_candidatepcilist < 0 || fragmentLength_candidatepcilist < 0 || fragmentLength_candidatepcilist > int64(^uint(0)>>1) || fragmentOffset_candidatepcilist > int64(^uint(0)>>1)-fragmentLength_candidatepcilist {
						return fmt.Errorf("collection fragment count out of range")
					}
					for i := int64(0); i < fragmentLength_candidatepcilist; i++ {
						var elem s17.CandidatePCI
						elementMark := extBB.EnterIndex(fragmentOffset_candidatepcilist + i)
						if err := s17.BridgeCandidatePCIMethodUnmarshalAPERFrom(&elem, extBB); err != nil {
							return runtime.WrapDecodePath(err, fmt.Sprintf("CandidatePCIList[%d]", fragmentOffset_candidatepcilist+i))
						}
						extBB.LeaveComponent(elementMark)
						if next, err := aper.AppendValues(extBB, tmp_candidatepcilist, elem); err != nil {
							return err
						} else {
							tmp_candidatepcilist = next
						}
					}
					return nil
				})
				if errCollection_candidatepcilist != nil {
					return runtime.WrapDecodePath(errCollection_candidatepcilist, "CandidatePCIList")
				}
				v.CandidatePCIList = tmp_candidatepcilist
				extBB.LeaveComponent(toleranceMark_candidatepcilist)
				padding, err := aper.CaptureOpenTypePadding(extBB)
				extBB.LeaveComponent(paddingMark)
				if err != nil {
					return runtime.WrapDecodePath(err, "ExtData_[0]")
				}
				v.perExtPadding[0] = padding
				return nil
			}(); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_COUNT_LOOP_1: 0 <= extCount < max int; gen/codegen_aper.go:605
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extCount; i++ {
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

type BridgeAsn1cAPERCandidateCellListListValue struct{ Value s21.CandidateCellList }
type BridgeAsn1cAPERCandidatePCIListListValue struct{ Value s17.CandidatePCIList }
type BridgeAsn1cAPERCellsToActivateListListValue struct{ Value s17.CellsToActivateList }

// MarshalAPER encodes CellActivationResponse to APER format.
func (v *CellActivationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *CellActivationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.ActivatedCellsList)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_activatedcellslist < 0 || fragmentOffset_activatedcellslist > int64(len(v.ActivatedCellsList)) || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(len(v.ActivatedCellsList[fragmentOffset_activatedcellslist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ActivatedCellsList[fragmentOffset_activatedcellslist : fragmentOffset_activatedcellslist+fragmentLength_activatedcellslist] {
			if err := s16.BridgeActivatedCellsListItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding activatedCellsList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding activatedCellsList: %w", err)
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

// UnmarshalAPER decodes CellActivationResponse from APER format.
func (v *CellActivationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellActivationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	bb.EnterComponent("CellActivationResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellActivationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	v.perPadding = padding
	return nil
}
func (v *CellActivationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellActivationResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_activatedcellslist := bb.EnterComponent("ActivatedCellsList")
	v.ActivatedCellsList = make(s16.ActivatedCellsList, 0)
	_, errCollection_activatedcellslist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_activatedcellslist, fragmentLength_activatedcellslist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_activatedcellslist < 0 || fragmentLength_activatedcellslist < 0 || fragmentLength_activatedcellslist > int64(^uint(0)>>1) || fragmentOffset_activatedcellslist > int64(^uint(0)>>1)-fragmentLength_activatedcellslist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_activatedcellslist; i++ {
			var elem s16.ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_activatedcellslist + i)
			if err := s16.BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ActivatedCellsList[%d]", fragmentOffset_activatedcellslist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ActivatedCellsList, elem); err != nil {
				return err
			} else {
				v.ActivatedCellsList = next
			}
		}
		return nil
	})
	if errCollection_activatedcellslist != nil {
		return runtime.WrapDecodePath(errCollection_activatedcellslist, "ActivatedCellsList")
	}
	bb.LeaveComponent(toleranceMark_activatedcellslist)
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

type BridgeAsn1cAPERActivatedCellsListListValue struct{ Value s16.ActivatedCellsList }
type BridgeAsn1cAPERNotificationCellListListValue struct{ Value s23.NotificationCellList }

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellActivationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellActivationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellActivationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellActivationResponse) WithoutReplay() CellActivationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellActivationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HOReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HOReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HOReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HOReport) WithoutReplay() HOReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HOReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellActivationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellActivationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellActivationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HOReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	for len(views) > 0 && views[0].Index() < 1 {
		views = views[1:]
	}
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HOReport) SetExtension(index uint64, contents []byte) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HOReport) RemoveExtension(index uint64) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HOReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellActivationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellActivationResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellActivationResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellActivationResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellActivationResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellActivationResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellActivationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellActivationResponse")
}
func (v *CellActivationResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellActivationResponse")
}
func (v *CellActivationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellActivationResponse(v, &s)
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
func (v *CellActivationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellActivationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HOReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HOReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HOReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HOReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHOReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HOReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HOReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HOReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HOReport")
}
func (v *HOReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HOReport")
}
func (v *HOReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHOReport(v, &s)
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
func (v *HOReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HOReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *CellActivationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellActivationResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellActivationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellActivationResponse{}
		return report, aper.OperationError(err, "CellActivationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellActivationResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HOReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HOReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HOReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHOReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HOReport{}
		return report, aper.OperationError(err, "HOReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HOReport")
}

type BearersSubjectToStatusTransferItemIEValue struct {
	id                                    s00.ProtocolIEID
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                aper.OpaqueOpenType
	isOpaque                              bool
	rowBearersSubjectToStatusTransferItem *BearersSubjectToStatusTransferItem
}

func (v BearersSubjectToStatusTransferItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(89):
		return v.rowBearersSubjectToStatusTransferItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of BearersSubjectToStatusTransferItemIEValue and reports whether the opaque alternative is selected.
func (v *BearersSubjectToStatusTransferItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToStatusTransferItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs"}}
}
func (BearersSubjectToStatusTransferItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(89):
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

// AsBearersSubjectToStatusTransferItem returns the selected BearersSubjectToStatusTransferItem value of BearersSubjectToStatusTransferItemIEValue and reports whether that alternative is active.
func (v *BearersSubjectToStatusTransferItemIEValue) AsBearersSubjectToStatusTransferItem() (*BearersSubjectToStatusTransferItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(89) || v.rowBearersSubjectToStatusTransferItem == nil {
		return nil, false
	}
	return v.rowBearersSubjectToStatusTransferItem, true
}
func (v BearersSubjectToStatusTransferItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToStatusTransferItemIEValue, error) {
	out := BearersSubjectToStatusTransferItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(89):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value BearersSubjectToStatusTransferItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToStatusTransferItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "BearersSubjectToStatusTransferItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowBearersSubjectToStatusTransferItem = &value
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
func (v BearersSubjectToStatusTransferItemIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToStatusTransferItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(89):
		if v.rowBearersSubjectToStatusTransferItem == nil {
			return nil, fmt.Errorf("%s missing value", "Bearers-SubjectToStatusTransfer-ItemIEs.id-Bearers-SubjectToStatusTransfer-Item:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowBearersSubjectToStatusTransferItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToStatusTransferItemIEValue:", v.id)
	}
}

type UserLocationInformationExtIEsValue struct {
	id                      s00.ProtocolIEID
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  aper.OpaqueOpenType
	isOpaque                bool
	rowPSCellInformation    *s23.PSCellInformation
	rowLTENTNTAIInformation *s22.LTENTNTAIInformation
}

func (v UserLocationInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UserLocationInformationExtIEsValue and reports whether the opaque alternative is selected.
func (v *UserLocationInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UserLocationInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs"}}
}
func (UserLocationInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(288):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
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

// AsPSCellInformation returns the selected PSCellInformation value of UserLocationInformationExtIEsValue and reports whether that alternative is active.
func (v *UserLocationInformationExtIEsValue) AsPSCellInformation() (*s23.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of UserLocationInformationExtIEsValue and reports whether that alternative is active.
func (v *UserLocationInformationExtIEsValue) AsLTENTNTAIInformation() (*s22.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v UserLocationInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UserLocationInformationExtIEsValue, error) {
	out := UserLocationInformationExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(288):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.PSCellInformation
		child := scope
		if err := s23.BridgePSCellInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PSCellInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PSCellInformation")
		if err != nil {
			return out, err
		}
		*s23.BridgePSCellInformationFieldPerPadding(&value) = padding
		*s23.BridgePSCellInformationFieldReceived(&value) = true
		raw.RetainContents(s23.BridgePSCellInformationFieldReceivedBytes(&value))
		*s23.BridgePSCellInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPSCellInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(339):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.LTENTNTAIInformation
		child := scope
		if err := s22.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s22.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s22.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s22.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowLTENTNTAIInformation = &value
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
func (v UserLocationInformationExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UserLocationInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UserLocationInformation-ExtIEs.id-PSCellInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgePSCellInformationMethodMarshalAPERBudget(v.rowPSCellInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UserLocationInformation-ExtIEs.id-LTE-NTN-TAI-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UserLocationInformationExtIEsValue:", v.id)
	}
}

type ENBStatusTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowMMEUES1APID                           *s00.MMEUES1APID
	rowENBUES1APID                           *s00.ENBUES1APID
	rowENBStatusTransferTransparentContainer *ENBStatusTransferTransparentContainer
}

func (v ENBStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(90):
		return v.rowENBStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs"}}
}
func (ENBStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(90):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBStatusTransferTransparentContainer returns the selected ENBStatusTransferTransparentContainer value of ENBStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBStatusTransferIEValue) AsENBStatusTransferTransparentContainer() (*ENBStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(90) || v.rowENBStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBStatusTransferTransparentContainer, true
}
func (v ENBStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBStatusTransferIEValue, error) {
	out := ENBStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(90):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBStatusTransferTransparentContainer = &value
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
func (v ENBStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(90):
		if v.rowENBStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "ENBStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBStatusTransferIEValue:", v.id)
	}
}

type MMEStatusTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowMMEUES1APID                           *s00.MMEUES1APID
	rowENBUES1APID                           *s00.ENBUES1APID
	rowENBStatusTransferTransparentContainer *ENBStatusTransferTransparentContainer
}

func (v MMEStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(90):
		return v.rowENBStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs"}}
}
func (MMEStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(90):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBStatusTransferTransparentContainer returns the selected ENBStatusTransferTransparentContainer value of MMEStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEStatusTransferIEValue) AsENBStatusTransferTransparentContainer() (*ENBStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(90) || v.rowENBStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBStatusTransferTransparentContainer, true
}
func (v MMEStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEStatusTransferIEValue, error) {
	out := MMEStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(90):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBStatusTransferTransparentContainer = &value
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
func (v MMEStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(90):
		if v.rowENBStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "MMEStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEStatusTransferIEValue:", v.id)
	}
}

// TS 36.413 V19.2.0 §9.3.7: the private selector owns its scalar pointers.
func BridgeClonePrivateID(id s23.PrivateIEID, budget *aper.DecodeBudget) (s23.PrivateIEID, error) {
	bb := aper.NewBudgetBuffer(budget)
	if id.Local != nil {
		if err := aper.ChargeValue(bb, *id.Local); err != nil {
			return s23.PrivateIEID{}, err
		}
		v := *id.Local
		id.Local = &v
	}
	if id.Global != nil {
		if err := aper.ChargeValue(bb, *id.Global); err != nil {
			return s23.PrivateIEID{}, err
		}
		v := *id.Global
		id.Global = &v
	}
	return id, nil
}

type BearersSubjectToStatusTransferItemIETable struct{}

func BearersSubjectToStatusTransferItemIEs() BearersSubjectToStatusTransferItemIETable {
	return BearersSubjectToStatusTransferItemIETable{}
}

// ID returns the ASN.1 object-set identity of BearersSubjectToStatusTransferItemIETable.
func (BearersSubjectToStatusTransferItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by BearersSubjectToStatusTransferItemIETable.
func (BearersSubjectToStatusTransferItemIETable) Table() s00.BearersSubjectToStatusTransferItemIEValueIETable {
	return func() s00.BearersSubjectToStatusTransferItemIEValueIETable {
		sealed := s00.BearersSubjectToStatusTransferItemIEValueIETable{}
		*s00.BridgeBearersSubjectToStatusTransferItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (BearersSubjectToStatusTransferItemIETable) infoBearersSubjectToStatusTransferItem() s00.FieldInfo {
	return s00.FieldInfo{Table: BearersSubjectToStatusTransferItemIEs().ID(), ID: s00.ProtocolIEID(89), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-Item"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToStatusTransfer-ItemIEs", Row: "id-Bearers-SubjectToStatusTransfer-Item"}}}
}

// BearersSubjectToStatusTransferItem returns the typed binding for the BearersSubjectToStatusTransferItem row of BearersSubjectToStatusTransferItemIETable.
func (t BearersSubjectToStatusTransferItemIETable) BearersSubjectToStatusTransferItem() BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding {
	return BearersSubjectToStatusTransferItemBearersSubjectToStatusTransferItemIEBinding{info: t.infoBearersSubjectToStatusTransferItem(), codec: BearersSubjectToStatusTransferItemValueCodec{path: "BearersSubjectToStatusTransferItem",
		decode: func(data []byte, options aper.DecodeState) (BearersSubjectToStatusTransferItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty BearersSubjectToStatusTransferItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToStatusTransferItem")
			var zero BearersSubjectToStatusTransferItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(89), raw)
			if err != nil {
				var empty BearersSubjectToStatusTransferItem
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferItem")
			}
			value, ok := decoded.AsBearersSubjectToStatusTransferItem()
			if !ok {
				var empty BearersSubjectToStatusTransferItem
				return empty, fmt.Errorf("binding Bearers-SubjectToStatusTransfer-ItemIEs.id-Bearers-SubjectToStatusTransfer-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value BearersSubjectToStatusTransferItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (BearersSubjectToStatusTransferItemIEValue{id: s00.ProtocolIEID(89), rowBearersSubjectToStatusTransferItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v BearersSubjectToStatusTransferItem, options aper.DecodeState) (BearersSubjectToStatusTransferItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APBearersSubjectToStatusTransferItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v BearersSubjectToStatusTransferItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBearersSubjectToStatusTransferItem(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToStatusTransferItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value BearersSubjectToStatusTransferItem) BearersSubjectToStatusTransferItemIEValue {
		return BearersSubjectToStatusTransferItemIEValue{id: s00.ProtocolIEID(89), rowBearersSubjectToStatusTransferItem: &value}
	}, get: func(value *BearersSubjectToStatusTransferItemIEValue) (*BearersSubjectToStatusTransferItem, bool) {
		return value.AsBearersSubjectToStatusTransferItem()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in BearersSubjectToStatusTransferItemIETable.
func (t BearersSubjectToStatusTransferItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (BearersSubjectToStatusTransferItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(89):
		return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-Bearers-SubjectToStatusTransfer-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return BearersSubjectToStatusTransferItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return BearersSubjectToStatusTransferItemIEField{Id: id, Criticality: criticality, Value: BearersSubjectToStatusTransferItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UserLocationInformationExtIETable struct{}

func UserLocationInformationExtIEs() UserLocationInformationExtIETable {
	return UserLocationInformationExtIETable{}
}

// ID returns the ASN.1 object-set identity of UserLocationInformationExtIETable.
func (UserLocationInformationExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UserLocationInformationExtIETable.
func (UserLocationInformationExtIETable) Table() s00.UserLocationInformationExtIEsValueExtensionTable {
	return func() s00.UserLocationInformationExtIEsValueExtensionTable {
		sealed := s00.UserLocationInformationExtIEsValueExtensionTable{}
		*s00.BridgeUserLocationInformationExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UserLocationInformationExtIETable) infoPSCellInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: UserLocationInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs", Row: "id-PSCellInformation"}}}
}

// PSCellInformation returns the typed binding for the PSCellInformation row of UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) PSCellInformation() UserLocationInformationExtIEsPSCellInformationExtBinding {
	return UserLocationInformationExtIEsPSCellInformationExtBinding{info: t.infoPSCellInformation(), codec: func() s23.PSCellInformationValueCodec {
		sealed := s23.PSCellInformationValueCodec{}
		*s23.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
		*s23.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PSCellInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.PSCellInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PSCellInformation")
			var zero UserLocationInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s23.PSCellInformation
				return empty, runtime.WrapDecodePath(err, "PSCellInformation")
			}
			value, ok := decoded.AsPSCellInformation()
			if !ok {
				var empty s23.PSCellInformation
				return empty, fmt.Errorf("binding UserLocationInformation-ExtIEs.id-PSCellInformation: no selected value")
			}
			return *value, nil
		}
		*s23.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s23.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgePSCellInformationValueCodecFieldCapture(&sealed) = func(v s23.PSCellInformation, options aper.DecodeState) (s23.PSCellInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APPSCellInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s23.BridgePSCellInformationValueCodecFieldCompare(&sealed) = func(v s23.PSCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APPSCellInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s23.BridgePSCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PSCellInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.PSCellInformation) UserLocationInformationExtIEsValue {
			return UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}
		}, get: func(value *UserLocationInformationExtIEsValue) (*s23.PSCellInformation, bool) {
			return value.AsPSCellInformation()
		}}
}
func (UserLocationInformationExtIETable) infoLTENTNTAIInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: UserLocationInformationExtIEs().ID(), ID: s00.ProtocolExtensionID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UserLocationInformation-ExtIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) LTENTNTAIInformation() UserLocationInformationExtIEsLTENTNTAIInformationExtBinding {
	return UserLocationInformationExtIEsLTENTNTAIInformationExtBinding{info: t.infoLTENTNTAIInformation(), codec: func() s22.LTENTNTAIInformationValueCodec {
		sealed := s22.LTENTNTAIInformationValueCodec{}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s22.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero UserLocationInformationExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s22.LTENTNTAIInformation
				return empty, fmt.Errorf("binding UserLocationInformation-ExtIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s22.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s22.LTENTNTAIInformation, options aper.DecodeState) (s22.LTENTNTAIInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s22.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.LTENTNTAIInformation) UserLocationInformationExtIEsValue {
			return UserLocationInformationExtIEsValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *UserLocationInformationExtIEsValue) (*s22.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UserLocationInformationExtIETable.
func (t UserLocationInformationExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (UserLocationInformationExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(288):
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return UserLocationInformationExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UserLocationInformationExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return UserLocationInformationExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: UserLocationInformationExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBStatusTransferIETable struct{}

func ENBStatusTransferIEs() ENBStatusTransferIETable { return ENBStatusTransferIETable{} }

// ID returns the ASN.1 object-set identity of ENBStatusTransferIETable.
func (ENBStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBStatusTransferIETable.
func (ENBStatusTransferIETable) Table() s00.ENBStatusTransferIEValueIETable {
	return func() s00.ENBStatusTransferIEValueIETable {
		sealed := s00.ENBStatusTransferIEValueIETable{}
		*s00.BridgeENBStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) MMEUES1APID() ENBStatusTransferMMEUES1APIDIEBinding {
	return ENBStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ENBStatusTransferIEValue {
			return ENBStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ENBStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ENBStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) ENBUES1APID() ENBStatusTransferENBUES1APIDIEBinding {
	return ENBStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBStatusTransferIEValue {
			return ENBStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBStatusTransferIETable) infoENBStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBStatusTransferIEs().ID(), ID: s00.ProtocolIEID(90), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-StatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBStatusTransferIEs", Row: "id-eNB-StatusTransfer-TransparentContainer"}}}
}

// ENBStatusTransferTransparentContainer returns the typed binding for the ENBStatusTransferTransparentContainer row of ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) ENBStatusTransferTransparentContainer() ENBStatusTransferENBStatusTransferTransparentContainerIEBinding {
	return ENBStatusTransferENBStatusTransferTransparentContainerIEBinding{info: t.infoENBStatusTransferTransparentContainer(), codec: ENBStatusTransferTransparentContainerValueCodec{path: "ENBStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBStatusTransferTransparentContainer")
			var zero ENBStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(90), raw)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBStatusTransferTransparentContainer()
			if !ok {
				var empty ENBStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding ENBStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBStatusTransferTransparentContainer, options aper.DecodeState) (ENBStatusTransferTransparentContainer, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			BridgeCaptureS1APENBStatusTransferTransparentContainer(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APENBStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBStatusTransferTransparentContainer) ENBStatusTransferIEValue {
		return ENBStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}
	}, get: func(value *ENBStatusTransferIEValue) (*ENBStatusTransferTransparentContainer, bool) {
		return value.AsENBStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBStatusTransferIETable.
func (t ENBStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(90):
		return ENBStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-StatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBStatusTransferIEField{Id: id, Criticality: criticality, Value: ENBStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEStatusTransferIETable struct{}

func MMEStatusTransferIEs() MMEStatusTransferIETable { return MMEStatusTransferIETable{} }

// ID returns the ASN.1 object-set identity of MMEStatusTransferIETable.
func (MMEStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEStatusTransferIETable.
func (MMEStatusTransferIETable) Table() s00.MMEStatusTransferIEValueIETable {
	return func() s00.MMEStatusTransferIEValueIETable {
		sealed := s00.MMEStatusTransferIEValueIETable{}
		*s00.BridgeMMEStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of MMEStatusTransferIETable.
func (t MMEStatusTransferIETable) MMEUES1APID() MMEStatusTransferMMEUES1APIDIEBinding {
	return MMEStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero MMEStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding MMEStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) MMEStatusTransferIEValue {
			return MMEStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *MMEStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (MMEStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of MMEStatusTransferIETable.
func (t MMEStatusTransferIETable) ENBUES1APID() MMEStatusTransferENBUES1APIDIEBinding {
	return MMEStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero MMEStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding MMEStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) MMEStatusTransferIEValue {
			return MMEStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *MMEStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (MMEStatusTransferIETable) infoENBStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEStatusTransferIEs().ID(), ID: s00.ProtocolIEID(90), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-StatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEStatusTransferIEs", Row: "id-eNB-StatusTransfer-TransparentContainer"}}}
}

// ENBStatusTransferTransparentContainer returns the typed binding for the ENBStatusTransferTransparentContainer row of MMEStatusTransferIETable.
func (t MMEStatusTransferIETable) ENBStatusTransferTransparentContainer() MMEStatusTransferENBStatusTransferTransparentContainerIEBinding {
	return MMEStatusTransferENBStatusTransferTransparentContainerIEBinding{info: t.infoENBStatusTransferTransparentContainer(), codec: ENBStatusTransferTransparentContainerValueCodec{path: "ENBStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBStatusTransferTransparentContainer")
			var zero MMEStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(90), raw)
			if err != nil {
				var empty ENBStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBStatusTransferTransparentContainer()
			if !ok {
				var empty ENBStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding MMEStatusTransferIEs.id-eNB-StatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBStatusTransferTransparentContainer, options aper.DecodeState) (ENBStatusTransferTransparentContainer, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			BridgeCaptureS1APENBStatusTransferTransparentContainer(
				&v,

				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APENBStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBStatusTransferTransparentContainer) MMEStatusTransferIEValue {
		return MMEStatusTransferIEValue{id: s00.ProtocolIEID(90), rowENBStatusTransferTransparentContainer: &value}
	}, get: func(value *MMEStatusTransferIEValue) (*ENBStatusTransferTransparentContainer, bool) {
		return value.AsENBStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEStatusTransferIETable.
func (t MMEStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(90):
		return MMEStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-StatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEStatusTransferIEField{Id: id, Criticality: criticality, Value: MMEStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UplinkS1cdma2000tunnellingIETable struct{}

func UplinkS1cdma2000tunnellingIEs() UplinkS1cdma2000tunnellingIETable {
	return UplinkS1cdma2000tunnellingIETable{}
}

// ID returns the ASN.1 object-set identity of UplinkS1cdma2000tunnellingIETable.
func (UplinkS1cdma2000tunnellingIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UplinkS1cdma2000tunnellingIETable.
func (UplinkS1cdma2000tunnellingIETable) Table() s00.UplinkS1cdma2000tunnellingIEValueIETable {
	return func() s00.UplinkS1cdma2000tunnellingIEValueIETable {
		sealed := s00.UplinkS1cdma2000tunnellingIEValueIETable{}
		*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) MMEUES1APID() s24.UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingMMEUES1APIDIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s24.BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = &value
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
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) ENBUES1APID() s24.UplinkS1cdma2000tunnellingENBUES1APIDIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingENBUES1APIDIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingENBUES1APIDIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s24.BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = &value
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
		*s24.BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000RATType() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(71), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000RATType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000RATType"}}}
}

// Cdma2000RATType returns the typed binding for the Cdma2000RATType row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000RATType() s24.UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000RATTypeIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInfo(&sealed) = t.infoCdma2000RATType()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldCodec(&sealed) = func() s00.Cdma2000RATTypeValueCodec {
			sealed := s00.Cdma2000RATTypeValueCodec{}
			*s00.BridgeCdma2000RATTypeValueCodecFieldPath(&sealed) = "Cdma2000RATType"
			*s00.BridgeCdma2000RATTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000RATType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.Cdma2000RATType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000RATType")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(71), raw)
				if err != nil {
					var empty s00.Cdma2000RATType
					return empty, runtime.WrapDecodePath(err, "Cdma2000RATType")
				}
				value, ok := decoded.AsCdma2000RATType()
				if !ok {
					var empty s00.Cdma2000RATType
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000RATType: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCdma2000RATTypeValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000RATType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCdma2000RATTypeValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000RATType, options aper.DecodeState) (s00.Cdma2000RATType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCdma2000RATType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCdma2000RATTypeValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000RATType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCdma2000RATType(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s00.BridgeCdma2000RATTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000RATType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldInject(&sealed) = func(value s00.Cdma2000RATType) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(71)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000RATType(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000RATTypeIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000RATType, bool) {
			return value.AsCdma2000RATType()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000SectorID() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(72), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000SectorID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000SectorID"}}}
}

// Cdma2000SectorID returns the typed binding for the Cdma2000SectorID row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000SectorID() s24.UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000SectorIDIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInfo(&sealed) = t.infoCdma2000SectorID()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldCodec(&sealed) = func() s00.Cdma2000SectorIDValueCodec {
			sealed := s00.Cdma2000SectorIDValueCodec{}
			*s00.BridgeCdma2000SectorIDValueCodecFieldPath(&sealed) = "Cdma2000SectorID"
			*s00.BridgeCdma2000SectorIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000SectorID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.Cdma2000SectorID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000SectorID")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(72), raw)
				if err != nil {
					var empty s00.Cdma2000SectorID
					return empty, runtime.WrapDecodePath(err, "Cdma2000SectorID")
				}
				value, ok := decoded.AsCdma2000SectorID()
				if !ok {
					var empty s00.Cdma2000SectorID
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000SectorID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCdma2000SectorIDValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000SectorID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(72)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCdma2000SectorIDValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000SectorID, options aper.DecodeState) (s00.Cdma2000SectorID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s00.BridgeCaptureS1APCdma2000SectorID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCdma2000SectorIDValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000SectorID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCdma2000SectorID(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s00.BridgeCdma2000SectorIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000SectorID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldInject(&sealed) = func(value s00.Cdma2000SectorID) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(72)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000SectorID(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000SectorIDIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000SectorID, bool) {
			return value.AsCdma2000SectorID()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000HORequiredIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(84), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000HORequiredIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000HORequiredIndication"}}}
}

// Cdma2000HORequiredIndication returns the typed binding for the Cdma2000HORequiredIndication row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000HORequiredIndication() s24.UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInfo(&sealed) = t.infoCdma2000HORequiredIndication()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldCodec(&sealed) = func() s00.Cdma2000HORequiredIndicationValueCodec {
			sealed := s00.Cdma2000HORequiredIndicationValueCodec{}
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldPath(&sealed) = "Cdma2000HORequiredIndication"
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000HORequiredIndication, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.Cdma2000HORequiredIndication
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000HORequiredIndication")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(84), raw)
				if err != nil {
					var empty s00.Cdma2000HORequiredIndication
					return empty, runtime.WrapDecodePath(err, "Cdma2000HORequiredIndication")
				}
				value, ok := decoded.AsCdma2000HORequiredIndication()
				if !ok {
					var empty s00.Cdma2000HORequiredIndication
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000HORequiredIndication: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000HORequiredIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(84)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000HORequiredIndication, options aper.DecodeState) (s00.Cdma2000HORequiredIndication, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCdma2000HORequiredIndication(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000HORequiredIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.
					Begin()
				s02.BridgeCompareS1APCdma2000HORequiredIndication(&v, &s)
				s.End(
					f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeCdma2000HORequiredIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000HORequiredIndication"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldInject(&sealed) = func(value s00.Cdma2000HORequiredIndication) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(84)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000HORequiredIndication(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000HORequiredIndicationIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000HORequiredIndication, bool) {
			return value.AsCdma2000HORequiredIndication()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000OneXSRVCCInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(102), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000OneXSRVCCInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000OneXSRVCCInfo"}}}
}

// Cdma2000OneXSRVCCInfo returns the typed binding for the Cdma2000OneXSRVCCInfo row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000OneXSRVCCInfo() s24.UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInfo(&sealed) = t.infoCdma2000OneXSRVCCInfo()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldCodec(&sealed) = func() s17.Cdma2000OneXSRVCCInfoValueCodec {
			sealed := s17.Cdma2000OneXSRVCCInfoValueCodec{}
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldPath(&sealed) = "Cdma2000OneXSRVCCInfo"
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cdma2000OneXSRVCCInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.Cdma2000OneXSRVCCInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000OneXSRVCCInfo")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(102), raw)
				if err != nil {
					var empty s17.Cdma2000OneXSRVCCInfo
					return empty, runtime.WrapDecodePath(err, "Cdma2000OneXSRVCCInfo")
				}
				value, ok := decoded.AsCdma2000OneXSRVCCInfo()
				if !ok {
					var empty s17.Cdma2000OneXSRVCCInfo
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXSRVCCInfo: no selected value")
				}
				return *value, nil
			}
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldEncode(&sealed) = func(value s17.Cdma2000OneXSRVCCInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(102)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldCapture(&sealed) = func(v s17.Cdma2000OneXSRVCCInfo, options aper.DecodeState) (s17.Cdma2000OneXSRVCCInfo, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s17.BridgeCaptureS1APCdma2000OneXSRVCCInfo(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldCompare(&sealed) = func(v s17.Cdma2000OneXSRVCCInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s17.BridgeCompareS1APCdma2000OneXSRVCCInfo(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s17.BridgeCdma2000OneXSRVCCInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXSRVCCInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldInject(&sealed) = func(value s17.Cdma2000OneXSRVCCInfo) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(102)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXSRVCCInfo(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXSRVCCInfoIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s17.Cdma2000OneXSRVCCInfo, bool) {
			return value.AsCdma2000OneXSRVCCInfo()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000OneXRAND() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(97), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000OneXRAND"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000OneXRAND"}}}
}

// Cdma2000OneXRAND returns the typed binding for the Cdma2000OneXRAND row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000OneXRAND() s24.UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000OneXRANDIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInfo(&sealed) = t.infoCdma2000OneXRAND()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldCodec(&sealed) = func() s00.Cdma2000OneXRANDValueCodec {
			sealed := s00.Cdma2000OneXRANDValueCodec{}
			*s00.BridgeCdma2000OneXRANDValueCodecFieldPath(&sealed) = "Cdma2000OneXRAND"
			*s00.BridgeCdma2000OneXRANDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000OneXRAND, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.Cdma2000OneXRAND
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000OneXRAND")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(97), raw)
				if err != nil {
					var empty s00.Cdma2000OneXRAND
					return empty, runtime.WrapDecodePath(err, "Cdma2000OneXRAND")
				}
				value, ok := decoded.AsCdma2000OneXRAND()
				if !ok {
					var empty s00.Cdma2000OneXRAND
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000OneXRAND: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCdma2000OneXRANDValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000OneXRAND, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(97)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCdma2000OneXRANDValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000OneXRAND, options aper.DecodeState) (s00.Cdma2000OneXRAND, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s00.BridgeCaptureS1APCdma2000OneXRAND(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCdma2000OneXRANDValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000OneXRAND, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCdma2000OneXRAND(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s00.BridgeCdma2000OneXRANDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXRAND"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldInject(&sealed) = func(value s00.Cdma2000OneXRAND) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(97)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000OneXRAND(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000OneXRANDIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000OneXRAND, bool) {
			return value.AsCdma2000OneXRAND()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoCdma2000PDU() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(70), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cdma2000PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-cdma2000PDU"}}}
}

// Cdma2000PDU returns the typed binding for the Cdma2000PDU row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) Cdma2000PDU() s24.UplinkS1cdma2000tunnellingCdma2000PDUIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingCdma2000PDUIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingCdma2000PDUIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInfo(&sealed) = t.infoCdma2000PDU()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldCodec(&sealed) = func() s00.Cdma2000PDUValueCodec {
			sealed := s00.Cdma2000PDUValueCodec{}
			*s00.BridgeCdma2000PDUValueCodecFieldPath(&sealed) = "Cdma2000PDU"
			*s00.BridgeCdma2000PDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000PDU, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.Cdma2000PDU
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cdma2000PDU")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(70), raw)
				if err != nil {
					var empty s00.Cdma2000PDU
					return empty, runtime.WrapDecodePath(err, "Cdma2000PDU")
				}
				value, ok := decoded.AsCdma2000PDU()
				if !ok {
					var empty s00.Cdma2000PDU
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-cdma2000PDU: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCdma2000PDUValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000PDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCdma2000PDUValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000PDU, options aper.DecodeState) (s00.Cdma2000PDU, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCdma2000PDU(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCdma2000PDUValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000PDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCdma2000PDU(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s00.BridgeCdma2000PDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000PDU"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldInject(&sealed) = func(value s00.Cdma2000PDU) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(70)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowCdma2000PDU(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingCdma2000PDUIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.Cdma2000PDU, bool) {
			return value.AsCdma2000PDU()
		}
		return sealed
	}()
}
func (UplinkS1cdma2000tunnellingIETable) infoEUTRANRoundTripDelayEstimationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: UplinkS1cdma2000tunnellingIEs().ID(), ID: s00.ProtocolIEID(140), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRANRoundTripDelayEstimationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UplinkS1cdma2000tunnellingIEs", Row: "id-EUTRANRoundTripDelayEstimationInfo"}}}
}

// EUTRANRoundTripDelayEstimationInfo returns the typed binding for the EUTRANRoundTripDelayEstimationInfo row of UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) EUTRANRoundTripDelayEstimationInfo() s24.UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding {
	return func() s24.UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding {
		sealed := s24.UplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBinding{}
		*s24.BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInfo(&sealed) = t.infoEUTRANRoundTripDelayEstimationInfo()
		*s24.BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldCodec(&sealed) = func() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
			sealed := s00.EUTRANRoundTripDelayEstimationInfoValueCodec{}
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldPath(&sealed) = "EUTRANRoundTripDelayEstimationInfo"
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANRoundTripDelayEstimationInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EUTRANRoundTripDelayEstimationInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EUTRANRoundTripDelayEstimationInfo")
				var zero s24.UplinkS1cdma2000tunnellingIEValue
				decoded, err := s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodDecode(zero, s00.ProtocolIEID(140), raw)
				if err != nil {
					var empty s00.EUTRANRoundTripDelayEstimationInfo
					return empty, runtime.WrapDecodePath(err, "EUTRANRoundTripDelayEstimationInfo")
				}
				value, ok := decoded.AsEUTRANRoundTripDelayEstimationInfo()
				if !ok {
					var empty s00.EUTRANRoundTripDelayEstimationInfo
					return empty, fmt.Errorf("binding UplinkS1cdma2000tunnellingIEs.id-EUTRANRoundTripDelayEstimationInfo: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldEncode(&sealed) = func(value s00.EUTRANRoundTripDelayEstimationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodEncodeFresh((func() s24.UplinkS1cdma2000tunnellingIEValue {
					sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(140)
					*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldCapture(&sealed) = func(v s00.EUTRANRoundTripDelayEstimationInfo, options aper.DecodeState) (s00.EUTRANRoundTripDelayEstimationInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APEUTRANRoundTripDelayEstimationInfo(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldCompare(&sealed) = func(v s00.EUTRANRoundTripDelayEstimationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APEUTRANRoundTripDelayEstimationInfo(
					&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeEUTRANRoundTripDelayEstimationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANRoundTripDelayEstimationInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s24.BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldInject(&sealed) = func(value s00.EUTRANRoundTripDelayEstimationInfo) s24.UplinkS1cdma2000tunnellingIEValue {
			return func() s24.UplinkS1cdma2000tunnellingIEValue {
				sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = s00.ProtocolIEID(140)
				*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldRowEUTRANRoundTripDelayEstimationInfo(&sealed) = &value
				return sealed
			}()
		}
		*s24.BridgeUplinkS1cdma2000tunnellingEUTRANRoundTripDelayEstimationInfoIEBindingFieldGet(&sealed) = func(value *s24.UplinkS1cdma2000tunnellingIEValue) (*s00.EUTRANRoundTripDelayEstimationInfo, bool) {
			return value.AsEUTRANRoundTripDelayEstimationInfo()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UplinkS1cdma2000tunnellingIETable.
func (t UplinkS1cdma2000tunnellingIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s24.UplinkS1cdma2000tunnellingIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(71):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000RATType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(72):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000SectorID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(84):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000HORequiredIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(102):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000OneXSRVCCInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(97):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000OneXRAND requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(70):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-cdma2000PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(140):
		return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRANRoundTripDelayEstimationInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s24.UplinkS1cdma2000tunnellingIEField{}, aper.OperationError(err, "Opaque")
		}
		return s24.UplinkS1cdma2000tunnellingIEField{Id: id, Criticality: criticality, Value: func() s24.UplinkS1cdma2000tunnellingIEValue {
			sealed := s24.UplinkS1cdma2000tunnellingIEValue{}
			*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldId(&sealed) = id
			*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldOpaque(&sealed) = opaque
			*s24.BridgeUplinkS1cdma2000tunnellingIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

// BearersSubjectToStatusTransferItemCodec binds the complete APER value type.
func BearersSubjectToStatusTransferItemCodec() BearersSubjectToStatusTransferItemValueCodec {
	return BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().Codec()
}

// Cdma2000HORequiredIndicationCodec binds the complete APER value type.
func Cdma2000HORequiredIndicationCodec() s00.Cdma2000HORequiredIndicationValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Codec()
}

// Cdma2000OneXRANDCodec binds the complete APER value type.
func Cdma2000OneXRANDCodec() s00.Cdma2000OneXRANDValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Codec()
}

// Cdma2000OneXSRVCCInfoCodec binds the complete APER value type.
func Cdma2000OneXSRVCCInfoCodec() s17.Cdma2000OneXSRVCCInfoValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Codec()
}

// Cdma2000SectorIDCodec binds the complete APER value type.
func Cdma2000SectorIDCodec() s00.Cdma2000SectorIDValueCodec {
	return UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Codec()
}

// CellActivationResponseCodec binds the complete source value type.
func CellActivationResponseCodec() CellActivationResponseValueCodec {
	return CellActivationResponseValueCodec{path: "CellActivationResponse", decode: func(data []byte, options aper.DecodeState) (CellActivationResponse, error) {
		var value CellActivationResponse
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellActivationResponse{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellActivationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellActivationResponse, options aper.DecodeState) (CellActivationResponse, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellActivationResponse(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellActivationResponse, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellActivationResponse(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellActivationResponse"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellBasedMDTCodec binds the complete source value type.
func CellBasedMDTCodec() CellBasedMDTValueCodec {
	return CellBasedMDTValueCodec{path: "CellBasedMDT", decode: func(data []byte, options aper.DecodeState) (CellBasedMDT, error) {
		var value CellBasedMDT
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellBasedMDT{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellBasedMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellBasedMDT, options aper.DecodeState) (CellBasedMDT, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellBasedMDT(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellBasedMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellBasedMDT(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellBasedMDT"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// CellBasedQMCCodec binds the complete source value type.
func CellBasedQMCCodec() CellBasedQMCValueCodec {
	return CellBasedQMCValueCodec{path: "CellBasedQMC", decode: func(data []byte, options aper.DecodeState) (CellBasedQMC, error) {
		var value CellBasedQMC
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return CellBasedQMC{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value CellBasedQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v CellBasedQMC, options aper.DecodeState) (CellBasedQMC, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APCellBasedQMC(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v CellBasedQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APCellBasedQMC(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellBasedQMC"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ENBStatusTransferTransparentContainerCodec binds the complete APER value type.
func ENBStatusTransferTransparentContainerCodec() ENBStatusTransferTransparentContainerValueCodec {
	return ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Codec()
}

// EUTRANRoundTripDelayEstimationInfoCodec binds the complete APER value type.
func EUTRANRoundTripDelayEstimationInfoCodec() s00.EUTRANRoundTripDelayEstimationInfoValueCodec {
	return UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Codec()
}

// EmergencyAreaIDCancelledItemCodec binds the complete source value type.
func EmergencyAreaIDCancelledItemCodec() EmergencyAreaIDCancelledItemValueCodec {
	return EmergencyAreaIDCancelledItemValueCodec{path: "EmergencyAreaIDCancelledItem", decode: func(data []byte, options aper.DecodeState) (EmergencyAreaIDCancelledItem, error) {
		var value EmergencyAreaIDCancelledItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EmergencyAreaIDCancelledItem{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EmergencyAreaIDCancelledItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EmergencyAreaIDCancelledItem, options aper.DecodeState) (EmergencyAreaIDCancelledItem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APEmergencyAreaIDCancelledItem(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v EmergencyAreaIDCancelledItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.
			Begin()
		BridgeCompareS1APEmergencyAreaIDCancelledItem(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDCancelledItem"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// HOReportCodec binds the complete source value type.
func HOReportCodec() HOReportValueCodec {
	return HOReportValueCodec{path: "HOReport", decode: func(data []byte, options aper.DecodeState) (HOReport, error) {
		var value HOReport
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return HOReport{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value HOReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v HOReport, options aper.DecodeState) (HOReport, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options)
		f := s.Begin()
		BridgeCaptureS1APHOReport(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HOReport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APHOReport(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HOReport"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// LTENTNTAIInformationCodec binds the complete APER value type.
func LTENTNTAIInformationCodec() s22.LTENTNTAIInformationValueCodec {
	return UserLocationInformationExtIEs().LTENTNTAIInformation().Codec()
}

// PSCellInformationCodec binds the complete APER value type.
func PSCellInformationCodec() s23.PSCellInformationValueCodec {
	return UserLocationInformationExtIEs().PSCellInformation().Codec()
}
func (r *ValidationReport) addIssue(issue ValidationIssue) {
	if err := r.reserveReport(issue.Location); err != nil {
		return
	}
	r.Issues = append(r.Issues, issue)
}
func (r *ValidationReport) addDeferred(item s00.DeferredCondition) {
	if err := r.reserveReport(item.Location); err != nil {
		return
	}
	r.Deferred = append(r.Deferred, item)
}
func (r *ValidationReport) addUnchecked(location aper.Location) {
	if err := r.reserveReport(location); err != nil {
		return
	}
	r.Unchecked = append(r.Unchecked, location)
}
func (r *ValidationReport) reserveReport(location aper.Location) error {
	if r.err != nil {
		return r.err
	}
	if r.budget == nil {
		return nil
	}
	bb := aper.NewBudgetBuffer(r.budget)
	if err := bb.ChargeLocatedReport(location, 1024); err != nil {
		r.err = err
		return err
	}
	return nil
}

type ValidationIssue struct {
	Code                s00.ValidationCode
	Severity            s00.ValidationSeverity
	Location            aper.Location
	Table               s00.TableID
	IEID                s00.ProtocolIEID
	HasIEID             bool
	PrivateID           *s23.PrivateIEID
	ExpectedCriticality *s00.Criticality
	ReceivedCriticality *s00.Criticality
	Rule                aper.SourceRule
	RelatedRules        []aper.SourceRule
}
type ValidationReport struct {
	budget    *aper.DecodeBudget
	err       error
	Issues    []ValidationIssue
	Deferred  []s00.DeferredCondition
	Unchecked []aper.Location
	Complete  bool
}

func BridgeBearersSubjectToStatusTransferItemIEFieldMethodMarshalAPERTo(v *BearersSubjectToStatusTransferItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemIEFieldMethodUnmarshalAPERFrom(v *BearersSubjectToStatusTransferItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldId(v *BearersSubjectToStatusTransferItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldIsOpaque(v *BearersSubjectToStatusTransferItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldOpaque(v *BearersSubjectToStatusTransferItemIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToStatusTransferItemIEValueFieldRowBearersSubjectToStatusTransferItem(v *BearersSubjectToStatusTransferItemIEValue) **BearersSubjectToStatusTransferItem {
	return &v.rowBearersSubjectToStatusTransferItem
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodMatchesID(v BearersSubjectToStatusTransferItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToStatusTransferItemIEValueMethodRule(v BearersSubjectToStatusTransferItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldCapture(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, aper.DecodeState) (BearersSubjectToStatusTransferList, aper.Snapshot) {
	return &v.capture
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldCompare(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldContext(v *BearersSubjectToStatusTransferListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldDecode(v *BearersSubjectToStatusTransferListValueCodec) *func([]byte, aper.DecodeState) (BearersSubjectToStatusTransferList, error) {
	return &v.decode
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldEncode(v *BearersSubjectToStatusTransferListValueCodec) *func(BearersSubjectToStatusTransferList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBearersSubjectToStatusTransferListValueCodecFieldPath(v *BearersSubjectToStatusTransferListValueCodec) *aper.Path {
	return &v.path
}
func BridgeCellActivationResponseMethodMarshalAPERTo(v *CellActivationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellActivationResponseMethodUnmarshalAPERFrom(v *CellActivationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellBasedMDTMethodMarshalAPERTo(v *CellBasedMDT, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedMDTMethodUnmarshalAPERFrom(v *CellBasedMDT, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellBasedQMCMethodMarshalAPERTo(v *CellBasedQMC, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeCellBasedQMCMethodUnmarshalAPERFrom(v *CellBasedQMC, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTrafficTraceFieldPerPadding(v *CellTrafficTrace) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeCellTrafficTraceFieldReceived(v *CellTrafficTrace) *bool { return &v.received }
func BridgeCellTrafficTraceFieldReceivedAbsolute(v *CellTrafficTrace) *bool {
	return &v.receivedAbsolute
}
func BridgeCellTrafficTraceFieldReceivedBytes(v *CellTrafficTrace) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellTrafficTraceFieldReceivedLocation(v *CellTrafficTrace) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellTrafficTraceMethodMarshalAPERBudget(v *CellTrafficTrace, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellTrafficTraceMethodUnmarshalAPERFrom(v *CellTrafficTrace, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeCellTrafficTraceMethodUnmarshalAPERWithOptions(v *CellTrafficTrace, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellTrafficTraceValueCodecFieldCapture(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, aper.DecodeState) (CellTrafficTrace, aper.Snapshot) {
	return &v.capture
}
func BridgeCellTrafficTraceValueCodecFieldCompare(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeCellTrafficTraceValueCodecFieldContext(v *CellTrafficTraceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeCellTrafficTraceValueCodecFieldDecode(v *CellTrafficTraceValueCodec) *func([]byte, aper.DecodeState) (CellTrafficTrace, error) {
	return &v.decode
}
func BridgeCellTrafficTraceValueCodecFieldEncode(v *CellTrafficTraceValueCodec) *func(CellTrafficTrace, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellTrafficTraceValueCodecFieldPath(v *CellTrafficTraceValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEContainerValueCodecFieldCapture(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, aper.DecodeState) (ENBStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEContainerValueCodecFieldCompare(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEContainerValueCodecFieldContext(v *ENBStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEContainerValueCodecFieldDecode(v *ENBStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEContainerValueCodecFieldEncode(v *ENBStatusTransferIEContainerValueCodec) *func(ENBStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEContainerValueCodecFieldPath(v *ENBStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEFieldFieldReplay(v *ENBStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBStatusTransferIEFieldFieldWithoutReplay(v *ENBStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(v *ENBStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBStatusTransferIEFieldMethodUnmarshalAPERFrom(v *ENBStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBStatusTransferIEFieldValueCodecFieldCapture(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, aper.DecodeState) (ENBStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEFieldValueCodecFieldCompare(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEFieldValueCodecFieldContext(v *ENBStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEFieldValueCodecFieldDecode(v *ENBStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEField, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEFieldValueCodecFieldEncode(v *ENBStatusTransferIEFieldValueCodec) *func(ENBStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEFieldValueCodecFieldPath(v *ENBStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueFieldId(v *ENBStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBStatusTransferIEValueFieldIsOpaque(v *ENBStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBStatusTransferIEValueFieldOpaque(v *ENBStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(v *ENBStatusTransferIEValue) **ENBStatusTransferTransparentContainer {
	return &v.rowENBStatusTransferTransparentContainer
}
func BridgeENBStatusTransferIEValueFieldRowENBUES1APID(v *ENBStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBStatusTransferIEValueFieldRowMMEUES1APID(v *ENBStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeENBStatusTransferIEValueMethodCaptureSemantics(v ENBStatusTransferIEValue, a0 aper.SemanticCapture) ENBStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBStatusTransferIEValueMethodCompareSemantics(v ENBStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBStatusTransferIEValueMethodMatchesID(v ENBStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBStatusTransferIEValueMethodRule(v ENBStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeEmergencyAreaIDCancelledItemMethodMarshalAPERTo(v *EmergencyAreaIDCancelledItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEmergencyAreaIDCancelledItemMethodUnmarshalAPERFrom(v *EmergencyAreaIDCancelledItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldCapture(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, aper.DecodeState) (EmergencyAreaIDCancelled, aper.Snapshot) {
	return &v.capture
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldCompare(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldContext(v *EmergencyAreaIDCancelledValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldDecode(v *EmergencyAreaIDCancelledValueCodec) *func([]byte, aper.DecodeState) (EmergencyAreaIDCancelled, error) {
	return &v.decode
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldEncode(v *EmergencyAreaIDCancelledValueCodec) *func(EmergencyAreaIDCancelled, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEmergencyAreaIDCancelledValueCodecFieldPath(v *EmergencyAreaIDCancelledValueCodec) *aper.Path {
	return &v.path
}
func BridgeHOReportMethodMarshalAPERTo(v *HOReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHOReportMethodUnmarshalAPERFrom(v *HOReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldCapture(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, aper.DecodeState) (MMEStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldCompare(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldContext(v *MMEStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldDecode(v *MMEStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldEncode(v *MMEStatusTransferIEContainerValueCodec) *func(MMEStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEContainerValueCodecFieldPath(v *MMEStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEFieldFieldReplay(v *MMEStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEStatusTransferIEFieldFieldWithoutReplay(v *MMEStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(v *MMEStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEStatusTransferIEFieldMethodUnmarshalAPERFrom(v *MMEStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldCapture(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, aper.DecodeState) (MMEStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldCompare(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldContext(v *MMEStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldDecode(v *MMEStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEField, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldEncode(v *MMEStatusTransferIEFieldValueCodec) *func(MMEStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEFieldValueCodecFieldPath(v *MMEStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEValueFieldId(v *MMEStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEStatusTransferIEValueFieldIsOpaque(v *MMEStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEStatusTransferIEValueFieldOpaque(v *MMEStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEStatusTransferIEValueFieldRowENBStatusTransferTransparentContainer(v *MMEStatusTransferIEValue) **ENBStatusTransferTransparentContainer {
	return &v.rowENBStatusTransferTransparentContainer
}
func BridgeMMEStatusTransferIEValueFieldRowENBUES1APID(v *MMEStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeMMEStatusTransferIEValueFieldRowMMEUES1APID(v *MMEStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeMMEStatusTransferIEValueMethodCaptureSemantics(v MMEStatusTransferIEValue, a0 aper.SemanticCapture) MMEStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEStatusTransferIEValueMethodCompareSemantics(v MMEStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEStatusTransferIEValueMethodMatchesID(v MMEStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEStatusTransferIEValueMethodRule(v MMEStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCapture(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldCompare(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldContext(v *UserLocationInformationExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldDecode(v *UserLocationInformationExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldEncode(v *UserLocationInformationExtIEsExtContainerValueCodec) *func(UserLocationInformationExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUserLocationInformationExtIEsExtContainerValueCodecFieldPath(v *UserLocationInformationExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v *UserLocationInformationExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v *UserLocationInformationExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(v *UserLocationInformationExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(v *UserLocationInformationExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCapture(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, aper.DecodeState) (UserLocationInformationExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCompare(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldContext(v *UserLocationInformationExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldDecode(v *UserLocationInformationExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (UserLocationInformationExtIEsExtField, error) {
	return &v.decode
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldEncode(v *UserLocationInformationExtIEsExtFieldValueCodec) *func(UserLocationInformationExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldPath(v *UserLocationInformationExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUserLocationInformationExtIEsValueFieldId(v *UserLocationInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUserLocationInformationExtIEsValueFieldIsOpaque(v *UserLocationInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeUserLocationInformationExtIEsValueFieldOpaque(v *UserLocationInformationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUserLocationInformationExtIEsValueFieldRowLTENTNTAIInformation(v *UserLocationInformationExtIEsValue) **s22.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeUserLocationInformationExtIEsValueFieldRowPSCellInformation(v *UserLocationInformationExtIEsValue) **s23.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgeUserLocationInformationExtIEsValueMethodCaptureSemantics(v UserLocationInformationExtIEsValue, a0 aper.SemanticCapture) UserLocationInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeUserLocationInformationExtIEsValueMethodCompareSemantics(v UserLocationInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUserLocationInformationExtIEsValueMethodMatchesID(v UserLocationInformationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUserLocationInformationExtIEsValueMethodRule(v UserLocationInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeValidationReportFieldBudget(v *ValidationReport) **aper.DecodeBudget { return &v.budget }
func BridgeValidationReportFieldErr(v *ValidationReport) *error                 { return &v.err }
func BridgeValidationReportMethodAddDeferred(v *ValidationReport, a0 s00.DeferredCondition) {
	v.addDeferred(a0)
}
func BridgeValidationReportMethodAddIssue(v *ValidationReport, a0 ValidationIssue) { v.addIssue(a0) }
func BridgeValidationReportMethodAddUnchecked(v *ValidationReport, a0 aper.Location) {
	v.addUnchecked(a0)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *BearersSubjectToStatusTransferItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 89:
		if value, ok := v.AsBearersSubjectToStatusTransferItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ENBStatusTransferIEValue) Selected() (any, bool) {
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
	case 90:
		if value, ok := v.AsENBStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *MMEStatusTransferIEValue) Selected() (any, bool) {
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
	case 90:
		if value, ok := v.AsENBStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UserLocationInformationExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 288:
		if value, ok := v.AsPSCellInformation(); ok {
			return value, true
		}
	case 339:
		if value, ok := v.AsLTENTNTAIInformation(); ok {
			return value, true
		}
	}
	return nil, false
}
