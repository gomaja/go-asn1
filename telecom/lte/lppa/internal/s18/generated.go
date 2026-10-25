// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s18 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s18

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// OTDOAInformationRequestIEContainer is ProtocolIE-Container {{OTDOAInformationRequest-IEs}} of TS 36.455: a list of OTDOAInformationRequestIEField values.
type OTDOAInformationRequestIEContainer []OTDOAInformationRequestIEField

// OTDOAInformationRequestIEField is ProtocolIE-Field {{OTDOAInformationRequest-IEs}} of TS 36.455: a field carrying a value of OTDOAInformationRequestIEValue.
type OTDOAInformationRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OTDOAInformationRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationRequestIEField) WithoutReplay() OTDOAInformationRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationRequestIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero OTDOAInformationRequestIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationResponseIEContainer is ProtocolIE-Container {{OTDOAInformationResponse-IEs}} of TS 36.455: a list of OTDOAInformationResponseIEField values.
type OTDOAInformationResponseIEContainer []OTDOAInformationResponseIEField

// OTDOAInformationResponseIEField is ProtocolIE-Field {{OTDOAInformationResponse-IEs}} of TS 36.455: a field carrying a value of OTDOAInformationResponseIEValue.
type OTDOAInformationResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OTDOAInformationResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationResponseIEField) WithoutReplay() OTDOAInformationResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationResponseIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero OTDOAInformationResponseIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(v *OTDOAInformationRequestIEContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(v *OTDOAInformationRequestIEContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(v *OTDOAInformationResponseIEContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(v *OTDOAInformationResponseIEContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// OTDOAInformationRequestOTDOAInformationTypeIEBinding binds OTDOAInformationType to ProtocolIE-Field {{OTDOAInformationRequest-IEs}} of TS 36.455.
type OTDOAInformationRequestOTDOAInformationTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s08.OTDOAInformationTypeValueCodec
	inject func(s07.OTDOAInformationType,

	) OTDOAInformationRequestIEValue

	get func(*OTDOAInformationRequestIEValue,

	) (*s07.OTDOAInformationType,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Codec() s08.OTDOAInformationTypeValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) New(value s07.OTDOAInformationType,

) (OTDOAInformationRequestIEField, error) {
	if b.inject == nil {
		return OTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s08.BridgeOTDOAInformationTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Get(field *OTDOAInformationRequestIEField) (*s07.OTDOAInformationType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseOTDOACellsIEBinding binds OTDOACells to ProtocolIE-Field {{OTDOAInformationResponse-IEs}} of TS 36.455.
type OTDOAInformationResponseOTDOACellsIEBinding struct {
	info   s00.FieldInfo
	codec  s16.OTDOACellsValueCodec
	inject func(s16.OTDOACells,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*s16.OTDOACells,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationResponseOTDOACellsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationResponseOTDOACellsIEBinding) Codec() s16.OTDOACellsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationResponseOTDOACellsIEBinding) New(value s16.OTDOACells,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeOTDOACellsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationResponseOTDOACellsIEBinding) Get(field *OTDOAInformationResponseIEField) (*s16.OTDOACells,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{OTDOAInformationResponse-IEs}} of TS 36.455.
type OTDOAInformationResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Get(field *OTDOAInformationResponseIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseAddOTDOACellsIEBinding binds AddOTDOACells to ProtocolIE-Field {{OTDOAInformationResponse-IEs}} of TS 36.455.
type OTDOAInformationResponseAddOTDOACellsIEBinding struct {
	info   s00.FieldInfo
	codec  s15.AddOTDOACellsValueCodec
	inject func(s15.AddOTDOACells,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*s15.AddOTDOACells,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Codec() s15.AddOTDOACellsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) New(value s15.AddOTDOACells,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s15.BridgeAddOTDOACellsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Get(field *OTDOAInformationResponseIEField) (*s15.AddOTDOACells,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationRequestValueCodec is the concrete ValueCodec[OTDOAInformationRequest].
type OTDOAInformationRequestValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOAInformationRequest, aper.DecodeState,

	) (OTDOAInformationRequest, aper.Snapshot,

	)
	compare func(OTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOAInformationRequest,

		error)
	encode func(OTDOAInformationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationRequestValueCodec) New(value OTDOAInformationRequest,

) (OTDOAInformationRequestAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationRequestAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationRequestValueCodec) EncodeAPER(value OTDOAInformationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c OTDOAInformationRequestValueCodec) encodeBudget(value OTDOAInformationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationRequestValueCodec) encodeChanged(value OTDOAInformationRequest,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOAInformationResponseValueCodec is the concrete ValueCodec[OTDOAInformationResponse].
type OTDOAInformationResponseValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOAInformationResponse, aper.DecodeState,

	) (OTDOAInformationResponse, aper.Snapshot,

	)
	compare func(OTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOAInformationResponse,

		error)
	encode func(OTDOAInformationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationResponseValueCodec) New(value OTDOAInformationResponse,

) (OTDOAInformationResponseAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationResponseValueCodec) EncodeAPER(value OTDOAInformationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c OTDOAInformationResponseValueCodec) encodeBudget(value OTDOAInformationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationResponseValueCodec) encodeChanged(value OTDOAInformationResponse,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(fields OTDOAInformationRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(fields OTDOAInformationResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// oTDOAInformationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) OTDOAInformationRequestIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (OTDOAInformationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(v *OTDOAInformationRequestIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEField(v *OTDOAInformationRequestIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// oTDOAInformationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) OTDOAInformationResponseIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (OTDOAInformationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(v *OTDOAInformationResponseIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEField(v *OTDOAInformationResponseIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// OTDOAInformationRequestAPERValue is the concrete APERValue[OTDOAInformationRequest].
type OTDOAInformationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOAInformationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationRequestAPERValue) WithoutReplay() OTDOAInformationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationResponseAPERValue is the concrete APERValue[OTDOAInformationResponse].
type OTDOAInformationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOAInformationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationResponseAPERValue) WithoutReplay() OTDOAInformationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesComplete carries a complete MeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasurementQuantitiesComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s06.MeasurementQuantities
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *MeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MeasurementQuantities from APER format.
func (v *MeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasurementQuantities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantities")
	}
	bb.EnterComponent("MeasurementQuantities")
	value, err := BridgeUnmarshalAPERMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantities")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasurementQuantities")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantities")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMeasurementQuantities encodes a MeasurementQuantities list to APER.
func BridgeMarshalAPERMeasurementQuantities(list MeasurementQuantitiesComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMeasurementQuantities decodes a MeasurementQuantities list from APER.
func BridgeUnmarshalAPERMeasurementQuantities(data []byte) (MeasurementQuantitiesComplete, error) {
	var value MeasurementQuantitiesComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMeasurementQuantitiesFrom decodes a MeasurementQuantities list from bb.
func BridgeUnmarshalAPERMeasurementQuantitiesFrom(bb *aper.BitBuffer) (s06.MeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMeasurementQuantitiesInto(v *s09.BridgeAsn1cAPERMeasurementQuantitiesListValue, bb *aper.BitBuffer) error {
	v.Value = make(s06.MeasurementQuantities, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s06.MeasurementQuantitiesItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s06.BridgeMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// MeasuredResultsComplete carries a complete MeasuredResults encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasuredResultsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s13.MeasuredResults
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *MeasuredResultsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERMeasuredResultsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MeasuredResults from APER format.
func (v *MeasuredResultsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasuredResults with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasuredResultsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResults")
	}
	bb.EnterComponent("MeasuredResults")
	value, err := BridgeUnmarshalAPERMeasuredResultsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResults")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasuredResults")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResults")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMeasuredResults encodes a MeasuredResults list to APER.
func BridgeMarshalAPERMeasuredResults(list MeasuredResultsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMeasuredResults decodes a MeasuredResults list from APER.
func BridgeUnmarshalAPERMeasuredResults(data []byte) (MeasuredResultsComplete, error) {
	var value MeasuredResultsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERMeasuredResultsFrom decodes a MeasuredResults list from bb.
func BridgeUnmarshalAPERMeasuredResultsFrom(bb *aper.BitBuffer) (s13.MeasuredResults, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s13.BridgeAsn1cAPERMeasuredResultsListValue
	if err := BridgeUnmarshalAPERMeasuredResultsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMeasuredResultsInto(v *s13.BridgeAsn1cAPERMeasuredResultsListValue, bb *aper.BitBuffer) error {
	v.Value = make(s13.MeasuredResults, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s13.MeasuredResultsValue
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s13.BridgeMeasuredResultsValueMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// MBSFNsubframeConfigurationComplete carries a complete MBSFNsubframeConfiguration encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNsubframeConfigurationComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s09.MBSFNsubframeConfiguration
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *MBSFNsubframeConfigurationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERMBSFNsubframeConfigurationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MBSFNsubframeConfiguration from APER format.
func (v *MBSFNsubframeConfigurationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNsubframeConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNsubframeConfigurationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	bb.EnterComponent("MBSFNsubframeConfiguration")
	value, err := s17.BridgeUnmarshalAPERMBSFNsubframeConfigurationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "MBSFNsubframeConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERMBSFNsubframeConfiguration encodes a MBSFNsubframeConfiguration list to APER.
func BridgeMarshalAPERMBSFNsubframeConfiguration(list MBSFNsubframeConfigurationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERMBSFNsubframeConfiguration decodes a MBSFNsubframeConfiguration list from APER.
func BridgeUnmarshalAPERMBSFNsubframeConfiguration(data []byte) (MBSFNsubframeConfigurationComplete, error) {
	var value MBSFNsubframeConfigurationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// OTDOACellsComplete carries a complete OTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s16.OTDOACells
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *OTDOACellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPEROTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOACells from APER format.
func (v *OTDOACellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACells")
	}
	bb.EnterComponent("OTDOACells")
	value, err := BridgeUnmarshalAPEROTDOACellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACells")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOACells")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACells")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEROTDOACells encodes a OTDOACells list to APER.
func BridgeMarshalAPEROTDOACells(list OTDOACellsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEROTDOACells decodes a OTDOACells list from APER.
func BridgeUnmarshalAPEROTDOACells(data []byte) (OTDOACellsComplete, error) {
	var value OTDOACellsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOACellsFrom decodes a OTDOACells list from bb.
func BridgeUnmarshalAPEROTDOACellsFrom(bb *aper.BitBuffer) (s16.OTDOACells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s16.BridgeAsn1cAPEROTDOACellsListValue
	if err := BridgeUnmarshalAPEROTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOACellsInto(v *s16.BridgeAsn1cAPEROTDOACellsListValue, bb *aper.BitBuffer) error {
	v.Value = make(s16.OTDOACells, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.OTDOACellsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeOTDOACellsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// OTDOACellInformationComplete carries a complete OTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellInformationComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s15.OTDOACellInformation
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *OTDOACellInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPEROTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOACellInformation from APER format.
func (v *OTDOACellInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellInformationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformation")
	}
	bb.EnterComponent("OTDOACellInformation")
	value, err := BridgeUnmarshalAPEROTDOACellInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOACellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOACellInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEROTDOACellInformation encodes a OTDOACellInformation list to APER.
func BridgeMarshalAPEROTDOACellInformation(list OTDOACellInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEROTDOACellInformation decodes a OTDOACellInformation list from APER.
func BridgeUnmarshalAPEROTDOACellInformation(data []byte) (OTDOACellInformationComplete, error) {
	var value OTDOACellInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOACellInformationFrom decodes a OTDOACellInformation list from bb.
func BridgeUnmarshalAPEROTDOACellInformationFrom(bb *aper.BitBuffer) (s15.OTDOACellInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s15.BridgeAsn1cAPEROTDOACellInformationListValue
	if err := BridgeUnmarshalAPEROTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOACellInformationInto(v *s15.BridgeAsn1cAPEROTDOACellInformationListValue, bb *aper.BitBuffer) error {
	v.Value = make(s15.OTDOACellInformation, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNsubframeConfigurationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNsubframeConfigurationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNsubframeConfigurationComplete) WithoutReplay() MBSFNsubframeConfigurationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MBSFNsubframeConfigurationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasuredResultsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasuredResultsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasuredResultsComplete) WithoutReplay() MeasuredResultsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MeasuredResultsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementQuantitiesComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementQuantitiesComplete) WithoutReplay() MeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellInformationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellInformationComplete) WithoutReplay() OTDOACellInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOACellInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellsComplete) WithoutReplay() OTDOACellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOACellsComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *MBSFNsubframeConfigurationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MBSFNsubframeConfigurationComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERMBSFNsubframeConfigurationTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *MeasuredResultsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasuredResultsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MeasuredResultsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasuredResultsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MeasuredResultsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MeasuredResultsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MeasuredResultsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MeasuredResultsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MeasuredResultsComplete")
}
func (v *MeasuredResultsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasuredResultsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasuredResultsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaMeasuredResultsComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasuredResultsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasuredResultsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s13.BridgeMarshalAPERMeasuredResultsTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *MeasurementQuantitiesComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MeasurementQuantitiesComplete")
}
func (v *MeasurementQuantitiesComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasurementQuantitiesComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasurementQuantitiesComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasurementQuantitiesComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasurementQuantitiesComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOACellInformationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOACellInformationComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOACellInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOACellInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOACellInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOACellInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOACellInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOACellInformationComplete")
}
func (v *OTDOACellInformationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellInformationComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellInformationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOACellInformationComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s16.BridgeMarshalAPEROTDOACellInformationTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOACellsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOACellsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOACellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOACellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOACellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOACellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOACellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOACellsComplete")
}
func (v *OTDOACellsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOACellsComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s16.BridgeMarshalAPEROTDOACellsTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MBSFNsubframeConfigurationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MBSFNsubframeConfigurationComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MBSFNsubframeConfigurationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMBSFNsubframeConfigurationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MBSFNsubframeConfigurationComplete{}
		return report, aper.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MBSFNsubframeConfigurationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasuredResultsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasuredResultsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MeasuredResultsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasuredResultsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MeasuredResultsComplete{}
		return report, aper.OperationError(err, "MeasuredResultsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasuredResultsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasurementQuantitiesComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MeasurementQuantitiesComplete{}
		return report, aper.OperationError(err, "MeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasurementQuantitiesComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellInformationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOACellInformationComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellInformationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellInformationComplete{}
		return report, aper.OperationError(err, "OTDOACellInformationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOACellInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOACellsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellsComplete{}
		return report, aper.OperationError(err, "OTDOACellsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOACellsComplete")
}

// MarshalAPERMeasurementQuantities encodes a complete named list.
func MarshalAPERMeasurementQuantities(v MeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMeasuredResults encodes a complete named list.
func MarshalAPERMeasuredResults(v MeasuredResultsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMBSFNsubframeConfiguration encodes a complete named list.
func MarshalAPERMBSFNsubframeConfiguration(v MBSFNsubframeConfigurationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEROTDOACells encodes a complete named list.
func MarshalAPEROTDOACells(v OTDOACellsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEROTDOACellInformation encodes a complete named list.
func MarshalAPEROTDOACellInformation(v OTDOACellInformationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERMeasurementQuantities decodes a complete named list.
func UnmarshalAPERMeasurementQuantities(data []byte, options ...aper.DecodeOption) (MeasurementQuantitiesComplete, aper.DecodeReport, error) {
	var v MeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMeasuredResults decodes a complete named list.
func UnmarshalAPERMeasuredResults(data []byte, options ...aper.DecodeOption) (MeasuredResultsComplete, aper.DecodeReport, error) {
	var v MeasuredResultsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMBSFNsubframeConfiguration decodes a complete named list.
func UnmarshalAPERMBSFNsubframeConfiguration(data []byte, options ...aper.DecodeOption) (MBSFNsubframeConfigurationComplete, aper.DecodeReport, error) {
	var v MBSFNsubframeConfigurationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEROTDOACells decodes a complete named list.
func UnmarshalAPEROTDOACells(data []byte, options ...aper.DecodeOption) (OTDOACellsComplete, aper.DecodeReport, error) {
	var v OTDOACellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEROTDOACellInformation decodes a complete named list.
func UnmarshalAPEROTDOACellInformation(data []byte, options ...aper.DecodeOption) (OTDOACellInformationComplete, aper.DecodeReport, error) {
	var v OTDOACellInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// OTDOAInformationRequest represents the ASN.1 type OTDOAInformationRequest (SEQUENCE).
type OTDOAInformationRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      OTDOAInformationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// OTDOAInformationResponse represents the ASN.1 type OTDOAInformationResponse (SEQUENCE).
type OTDOAInformationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      OTDOAInformationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                `asn1:"-" json:"-"`
	extCount         int64                               `asn1:"-" json:"-"`
	extPresent       []bool                              `asn1:"-" json:"-"`
	extData          [][]byte                            `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                   `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding              `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes OTDOAInformationRequest to APER format.
func (v *OTDOAInformationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			replay.
			ReplayTo(v.stream, bb); ok ||
			err !=
				nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
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
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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

// UnmarshalAPER decodes OTDOAInformationRequest from APER format.
func (v *OTDOAInformationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	bb.EnterComponent("OTDOAInformationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOAInformationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(OTDOAInformationRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OTDOAInformationRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// OTDOAInformationTypeComplete carries a complete OTDOAInformationType encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOAInformationTypeComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s07.OTDOAInformationType
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *OTDOAInformationTypeComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPEROTDOAInformationTypeTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOAInformationType from APER format.
func (v *OTDOAInformationTypeComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationTypeComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationType")
	}
	bb.EnterComponent("OTDOAInformationType")
	value, err := BridgeUnmarshalAPEROTDOAInformationTypeFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationType")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOAInformationType")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationType")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEROTDOAInformationType encodes a OTDOAInformationType list to APER.
func BridgeMarshalAPEROTDOAInformationType(list OTDOAInformationTypeComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPEROTDOAInformationType decodes a OTDOAInformationType list from APER.
func BridgeUnmarshalAPEROTDOAInformationType(data []byte) (OTDOAInformationTypeComplete, error) {
	var value OTDOAInformationTypeComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEROTDOAInformationTypeFrom decodes a OTDOAInformationType list from bb.
func BridgeUnmarshalAPEROTDOAInformationTypeFrom(bb *aper.BitBuffer) (s07.OTDOAInformationType, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPEROTDOAInformationTypeListValue
	if err := BridgeUnmarshalAPEROTDOAInformationTypeInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOAInformationTypeInto(v *s09.BridgeAsn1cAPEROTDOAInformationTypeListValue, bb *aper.BitBuffer) error {
	v.Value = make(s07.OTDOAInformationType, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s07.OTDOAInformationTypeIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s07.BridgeOTDOAInformationTypeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationResponse to APER format.
func (v *OTDOAInformationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			replay.
			ReplayTo(v.stream, bb); ok ||
			err !=
				nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
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
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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

// UnmarshalAPER decodes OTDOAInformationResponse from APER format.
func (v *OTDOAInformationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	bb.EnterComponent("OTDOAInformationResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOAInformationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(OTDOAInformationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OTDOAInformationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOAInformationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationRequest) WithoutReplay() OTDOAInformationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOAInformationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOAInformationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationResponse) WithoutReplay() OTDOAInformationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOAInformationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOAInformationTypeComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationTypeComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationTypeComplete) WithoutReplay() OTDOAInformationTypeComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOAInformationTypeComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOAInformationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationRequest")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOAInformationRequest")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOAInformationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOAInformationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOAInformationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOAInformationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOAInformationRequest")
}
func (v *OTDOAInformationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationRequest) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOAInformationRequest(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOAInformationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOAInformationResponse")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOAInformationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOAInformationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOAInformationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOAInformationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOAInformationResponse")
}
func (v *OTDOAInformationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationResponse) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOAInformationResponse(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOAInformationTypeComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationTypeComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOAInformationTypeComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationTypeComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOAInformationTypeComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOAInformationTypeComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOAInformationTypeComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOAInformationTypeComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOAInformationTypeComplete")
}
func (v *OTDOAInformationTypeComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationTypeComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationTypeComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOAInformationTypeComplete(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationTypeComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationTypeComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPEROTDOAInformationTypeTo(value.Value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOAInformationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationRequest")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationRequest{}
		return report, aper.OperationError(err, "OTDOAInformationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOAInformationRequest")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOAInformationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationResponse")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationResponse{}
		return report, aper.OperationError(err, "OTDOAInformationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOAInformationResponse")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOAInformationTypeComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationTypeComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationTypeComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationTypeComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationTypeComplete{}
		return report, aper.OperationError(err, "OTDOAInformationTypeComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOAInformationTypeComplete")
}

// MarshalAPEROTDOAInformationType encodes a complete named list.
func MarshalAPEROTDOAInformationType(v OTDOAInformationTypeComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPEROTDOAInformationType decodes a complete named list.
func UnmarshalAPEROTDOAInformationType(data []byte, options ...aper.DecodeOption) (OTDOAInformationTypeComplete, aper.DecodeReport, error) {
	var v OTDOAInformationTypeComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}
func BridgeCaptureLPPaMBSFNsubframeConfigurationComplete(v *MBSFNsubframeConfigurationComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s09.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMBSFNsubframeConfigurationComplete(v *MBSFNsubframeConfigurationComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s10.BridgeCompareLPPaMBSFNsubframeConfiguration(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasuredResultsComplete(v *MeasuredResultsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s13.BridgeCaptureLPPaMeasuredResults(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasuredResultsComplete(v *MeasuredResultsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s13.BridgeCompareLPPaMeasuredResults(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasurementQuantitiesComplete(v *MeasurementQuantitiesComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s11.BridgeCaptureLPPaMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasurementQuantitiesComplete(v *MeasurementQuantitiesComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s11.BridgeCompareLPPaMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellInformationComplete(v *OTDOACellInformationComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s15.BridgeCaptureLPPaOTDOACellInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellInformationComplete(v *OTDOACellInformationComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s15.BridgeCompareLPPaOTDOACellInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellsComplete(v *OTDOACellsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s16.BridgeCaptureLPPaOTDOACells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellsComplete(v *OTDOACellsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s16.BridgeCompareLPPaOTDOACells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationRequest(v *OTDOAInformationRequest, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationRequest(v *OTDOAInformationRequest, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationRequestIEValue(v *OTDOAInformationRequestIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(9):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeGroup == nil)
				if v.rowOTDOAInformationTypeGroup != nil {
					s12.BridgeCaptureLPPaOTDOAInformationType(v.rowOTDOAInformationTypeGroup, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationRequestIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOAInformationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationRequestIEValue) captureSemantics(s aper.SemanticCapture) OTDOAInformationRequestIEValue {
	BridgeCaptureLPPaOTDOAInformationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationRequestIEValue(v *OTDOAInformationRequestIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(9):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeGroup == nil)
				if v.rowOTDOAInformationTypeGroup != nil {
					s12.BridgeCompareLPPaOTDOAInformationType(v.rowOTDOAInformationTypeGroup, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationRequestIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationRequestIEValue) WithoutReplay() OTDOAInformationRequestIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationResponse(v *OTDOAInformationResponse, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationResponse(v *OTDOAInformationResponse, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationResponseIEValue(v *OTDOAInformationResponseIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOACells == nil)
				if v.rowOTDOACells != nil {
					s16.BridgeCaptureLPPaOTDOACells(v.rowOTDOACells, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowAddOTDOACells == nil)
				if v.rowAddOTDOACells != nil {
					s15.BridgeCaptureLPPaAddOTDOACells(v.rowAddOTDOACells, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationResponseIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOAInformationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationResponseIEValue) captureSemantics(s aper.SemanticCapture) OTDOAInformationResponseIEValue {
	BridgeCaptureLPPaOTDOAInformationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationResponseIEValue(v *OTDOAInformationResponseIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOACells == nil)
				if v.rowOTDOACells != nil {
					s16.BridgeCompareLPPaOTDOACells(v.rowOTDOACells, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowAddOTDOACells == nil)
				if v.rowAddOTDOACells != nil {
					s15.BridgeCompareLPPaAddOTDOACells(v.rowAddOTDOACells, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationResponseIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationResponseIEValue) WithoutReplay() OTDOAInformationResponseIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationTypeComplete(v *OTDOAInformationTypeComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s12.BridgeCaptureLPPaOTDOAInformationType(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationTypeComplete(v *OTDOAInformationTypeComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s12.BridgeCompareLPPaOTDOAInformationType(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

type OTDOAInformationRequestIEValue struct {
	id                           s00.ProtocolIEID
	withoutReplay                bool
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       *aper.OpaqueOpenType
	isOpaque                     bool
	rowOTDOAInformationTypeGroup *s07.OTDOAInformationType
}

func (v OTDOAInformationRequestIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(9):
		return v.rowOTDOAInformationTypeGroup != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOAInformationRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs"}}
}
func (OTDOAInformationRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(9):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	default:
		return aper.UnknownSelector
	}
}

// AsOTDOAInformationTypeGroup returns the selected OTDOAInformationTypeGroup value and reports whether that alternative is active.
func (v *OTDOAInformationRequestIEValue) AsOTDOAInformationTypeGroup() (*s07.OTDOAInformationType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(9) || v.rowOTDOAInformationTypeGroup == nil {
		return nil, false
	}
	return v.rowOTDOAInformationTypeGroup, true
}
func (v OTDOAInformationRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOAInformationRequestIEValue, error) {
	out := OTDOAInformationRequestIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 9:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(9):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPEROTDOAInformationTypeFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "OTDOAInformationTypeGroup:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := OTDOAInformationTypeComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOAInformationTypeGroup = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v OTDOAInformationRequestIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(9):
		if v.rowOTDOAInformationTypeGroup == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationRequest-IEs.id-OTDOA-Information-Type-Group:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := OTDOAInformationTypeComplete{Value: *v.rowOTDOAInformationTypeGroup}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOAInformationRequestIEValue:", v.id)
	}
}

type OTDOAInformationResponseIEValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowOTDOACells             *s16.OTDOACells
	rowCriticalityDiagnostics *s09.CriticalityDiagnostics
	rowAddOTDOACells          *s15.AddOTDOACells
}

func (v OTDOAInformationResponseIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowOTDOACells != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(18):
		return v.rowAddOTDOACells != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOAInformationResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs"}}
}
func (OTDOAInformationResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(18):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
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
	default:
		return aper.UnknownSelector
	}
}

// AsOTDOACells returns the selected OTDOACells value and reports whether that alternative is active.
func (v *OTDOAInformationResponseIEValue) AsOTDOACells() (*s16.OTDOACells, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowOTDOACells == nil {
		return nil, false
	}
	return v.rowOTDOACells, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *OTDOAInformationResponseIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsAddOTDOACells returns the selected AddOTDOACells value and reports whether that alternative is active.
func (v *OTDOAInformationResponseIEValue) AsAddOTDOACells() (*s15.AddOTDOACells, bool) {
	if v == nil || v.id != s00.ProtocolIEID(18) || v.rowAddOTDOACells == nil {
		return nil, false
	}
	return v.rowAddOTDOACells, true
}
func (v OTDOAInformationResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOAInformationResponseIEValue, error) {
	out := OTDOAInformationResponseIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 8, 1, 18:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(8):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPEROTDOACellsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "OTDOACells:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := OTDOACellsComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOACells = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(18):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := s17.BridgeUnmarshalAPERAddOTDOACellsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AddOTDOACells:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() s17.AddOTDOACellsComplete {
			sealed := s17.AddOTDOACellsComplete{Value: list}
			*s17.BridgeAddOTDOACellsCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAddOTDOACells = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v OTDOAInformationResponseIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(8):
		if v.rowOTDOACells == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-OTDOACells:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := OTDOACellsComplete{Value: *v.rowOTDOACells}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(18):
		if v.rowAddOTDOACells == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-AddOTDOACells:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := s17.AddOTDOACellsComplete{Value: *v.rowAddOTDOACells}
		candidate, err := s17.BridgeAddOTDOACellsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOAInformationResponseIEValue:", v.id)
	}
}

type OTDOAInformationRequestIETable struct{}

func OTDOAInformationRequestIEs() OTDOAInformationRequestIETable {
	return OTDOAInformationRequestIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOAInformationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs"}
		return sealed
	}()
}
func (OTDOAInformationRequestIETable) infoOTDOAInformationTypeGroup() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationRequestIEs().ID(), ID: s00.ProtocolIEID(9), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs", Row: "id-OTDOA-Information-Type-Group"}}}
}

// OTDOAInformationTypeGroup returns the typed binding for the OTDOAInformationTypeGroup row of this table.
func (t OTDOAInformationRequestIETable) OTDOAInformationTypeGroup() OTDOAInformationRequestOTDOAInformationTypeIEBinding {
	return OTDOAInformationRequestOTDOAInformationTypeIEBinding{info: t.infoOTDOAInformationTypeGroup(), codec: func() s08.OTDOAInformationTypeValueCodec {
		sealed := s08.OTDOAInformationTypeValueCodec{}
		*s08.BridgeOTDOAInformationTypeValueCodecFieldPath(&sealed) = "OTDOAInformationType"
		*s08.BridgeOTDOAInformationTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.OTDOAInformationType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s07.OTDOAInformationType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("OTDOAInformationType")
			var zero OTDOAInformationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(9), raw)
			if err != nil {
				var empty s07.OTDOAInformationType
				return empty, runtime.WrapDecodePath(err, "OTDOAInformationType")
			}
			value, ok := decoded.AsOTDOAInformationTypeGroup()
			if !ok {
				var empty s07.OTDOAInformationType
				return empty, fmt.Errorf("binding OTDOAInformationRequest-IEs.id-OTDOA-Information-Type-Group: no selected value")
			}
			return *value, nil
		}
		*s08.BridgeOTDOAInformationTypeValueCodecFieldEncode(&sealed) = func(value s07.OTDOAInformationType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationRequestIEValue{id: s00.ProtocolIEID(9), rowOTDOAInformationTypeGroup: &value}).encodeFresh(fresh, budget)
		}
		*s08.BridgeOTDOAInformationTypeValueCodecFieldCapture(&sealed) = func(v s07.OTDOAInformationType, options aper.DecodeState) (s07.OTDOAInformationType, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s12.BridgeCaptureLPPaOTDOAInformationType(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s08.BridgeOTDOAInformationTypeValueCodecFieldCompare(&sealed) = func(v s07.OTDOAInformationType, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s12.BridgeCompareLPPaOTDOAInformationType(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s08.BridgeOTDOAInformationTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationType"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s07.OTDOAInformationType) OTDOAInformationRequestIEValue {
			return OTDOAInformationRequestIEValue{id: s00.ProtocolIEID(9), rowOTDOAInformationTypeGroup: &value}
		}, get: func(value *OTDOAInformationRequestIEValue) (*s07.OTDOAInformationType, bool) {
			return value.AsOTDOAInformationTypeGroup()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOAInformationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOAInformationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(9):
		return OTDOAInformationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-OTDOA-Information-Type-Group requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOAInformationRequestIEField{Id: id, Criticality: criticality, Value: OTDOAInformationRequestIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationResponseIETable struct{}

func OTDOAInformationResponseIEs() OTDOAInformationResponseIETable {
	return OTDOAInformationResponseIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOAInformationResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs"}
		return sealed
	}()
}
func (OTDOAInformationResponseIETable) infoOTDOACells() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-OTDOACells"}}}
}

// OTDOACells returns the typed binding for the OTDOACells row of this table.
func (t OTDOAInformationResponseIETable) OTDOACells() OTDOAInformationResponseOTDOACellsIEBinding {
	return OTDOAInformationResponseOTDOACellsIEBinding{info: t.infoOTDOACells(), codec: func() s16.OTDOACellsValueCodec {
		sealed := s16.OTDOACellsValueCodec{}
		*s16.BridgeOTDOACellsValueCodecFieldPath(&sealed) = "OTDOACells"
		*s16.BridgeOTDOACellsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.OTDOACells, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s16.OTDOACells
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("OTDOACells")
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s16.OTDOACells
				return empty, runtime.WrapDecodePath(err, "OTDOACells")
			}
			value, ok := decoded.AsOTDOACells()
			if !ok {
				var empty s16.OTDOACells
				return empty, fmt.Errorf("binding OTDOAInformationResponse-IEs.id-OTDOACells: no selected value")
			}
			return *value, nil
		}
		*s16.BridgeOTDOACellsValueCodecFieldEncode(&sealed) = func(value s16.OTDOACells, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(8), rowOTDOACells: &value}).encodeFresh(fresh, budget)
		}
		*s16.BridgeOTDOACellsValueCodecFieldCapture(&sealed) = func(v s16.OTDOACells, options aper.DecodeState) (s16.OTDOACells, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s16.BridgeCaptureLPPaOTDOACells(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*s16.BridgeOTDOACellsValueCodecFieldCompare(&sealed) = func(v s16.OTDOACells, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s16.BridgeCompareLPPaOTDOACells(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s16.BridgeOTDOACellsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACells"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s16.OTDOACells) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(8), rowOTDOACells: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*s16.OTDOACells, bool) { return value.AsOTDOACells() }}
}
func (OTDOAInformationResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t OTDOAInformationResponseIETable) CriticalityDiagnostics() OTDOAInformationResponseCriticalityDiagnosticsIEBinding {
	return OTDOAInformationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding OTDOAInformationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (OTDOAInformationResponseIETable) infoAddOTDOACells() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: s00.ProtocolIEID(18), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AddOTDOACells"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-AddOTDOACells"}}}
}

// AddOTDOACells returns the typed binding for the AddOTDOACells row of this table.
func (t OTDOAInformationResponseIETable) AddOTDOACells() OTDOAInformationResponseAddOTDOACellsIEBinding {
	return OTDOAInformationResponseAddOTDOACellsIEBinding{info: t.infoAddOTDOACells(), codec: func() s15.AddOTDOACellsValueCodec {
		sealed := s15.AddOTDOACellsValueCodec{}
		*s15.BridgeAddOTDOACellsValueCodecFieldPath(&sealed) = "AddOTDOACells"
		*s15.BridgeAddOTDOACellsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.AddOTDOACells, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s15.AddOTDOACells
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AddOTDOACells")
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(18), raw)
			if err != nil {
				var empty s15.AddOTDOACells
				return empty, runtime.WrapDecodePath(err, "AddOTDOACells")
			}
			value, ok := decoded.AsAddOTDOACells()
			if !ok {
				var empty s15.AddOTDOACells
				return empty, fmt.Errorf("binding OTDOAInformationResponse-IEs.id-AddOTDOACells: no selected value")
			}
			return *value, nil
		}
		*s15.BridgeAddOTDOACellsValueCodecFieldEncode(&sealed) = func(value s15.AddOTDOACells, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(18), rowAddOTDOACells: &value}).encodeFresh(fresh, budget)
		}
		*s15.BridgeAddOTDOACellsValueCodecFieldCapture(&sealed) = func(v s15.AddOTDOACells, options aper.DecodeState) (s15.AddOTDOACells, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeCaptureLPPaAddOTDOACells(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeAddOTDOACellsValueCodecFieldCompare(&sealed) = func(v s15.AddOTDOACells, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s15.BridgeCompareLPPaAddOTDOACells(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s15.BridgeAddOTDOACellsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACells"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s15.AddOTDOACells) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: s00.ProtocolIEID(18), rowAddOTDOACells: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*s15.AddOTDOACells, bool) {
			return value.AsAddOTDOACells()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOAInformationResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOAInformationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-OTDOACells requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(18):
		return OTDOAInformationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-AddOTDOACells requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOAInformationResponseIEField{Id: id, Criticality: criticality, Value: OTDOAInformationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AddOTDOACellsCodec binds the complete APER value type.
func AddOTDOACellsCodec() s15.AddOTDOACellsValueCodec {
	return OTDOAInformationResponseIEs().AddOTDOACells().Codec()
}

// MBSFNsubframeConfigurationCodec binds the complete source value type.
func MBSFNsubframeConfigurationCodec() s09.MBSFNsubframeConfigurationConcreteValueCodec {
	return func() s09.MBSFNsubframeConfigurationConcreteValueCodec {
		sealed := s09.MBSFNsubframeConfigurationConcreteValueCodec{}
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldPath(&sealed) = "MBSFNsubframeConfiguration"
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.MBSFNsubframeConfiguration, error) {
			var complete MBSFNsubframeConfigurationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s09.MBSFNsubframeConfiguration
				return zero, err
			}
			return complete.Value, nil
		}
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldEncode(&sealed) = func(value s09.MBSFNsubframeConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := MBSFNsubframeConfigurationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCapture(&sealed) = func(v s09.MBSFNsubframeConfiguration, options aper.DecodeState) (s09.MBSFNsubframeConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCompare(&sealed) = func(v s09.MBSFNsubframeConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s10.BridgeCompareLPPaMBSFNsubframeConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNsubframeConfiguration"
			return sealed
		}()
		return sealed
	}()

}

// MeasuredResultsCodec binds the complete source value type.
func MeasuredResultsCodec() s13.MeasuredResultsConcreteValueCodec {
	return func() s13.MeasuredResultsConcreteValueCodec {
		sealed := s13.MeasuredResultsConcreteValueCodec{}
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldPath(&sealed) = "MeasuredResults"
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.MeasuredResults, error) {
			var complete MeasuredResultsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s13.MeasuredResults
				return zero, err
			}
			return complete.Value, nil
		}
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldEncode(&sealed) = func(value s13.MeasuredResults, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := MeasuredResultsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldCapture(&sealed) = func(v s13.MeasuredResults, options aper.DecodeState) (s13.MeasuredResults, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s13.BridgeCaptureLPPaMeasuredResults(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldCompare(&sealed) = func(v s13.MeasuredResults, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s13.BridgeCompareLPPaMeasuredResults(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s13.BridgeMeasuredResultsConcreteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasuredResults"
			return sealed
		}()
		return sealed
	}()

}

// OTDOACellInformationCodec binds the complete source value type.
func OTDOACellInformationCodec() s15.OTDOACellInformationValueCodec {
	return func() s15.OTDOACellInformationValueCodec {
		sealed := s15.OTDOACellInformationValueCodec{}
		*s15.BridgeOTDOACellInformationValueCodecFieldPath(&sealed) = "OTDOACellInformation"
		*s15.BridgeOTDOACellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.OTDOACellInformation, error) {
			var complete OTDOACellInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s15.OTDOACellInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*s15.BridgeOTDOACellInformationValueCodecFieldEncode(&sealed) = func(value s15.OTDOACellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := OTDOACellInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s15.BridgeOTDOACellInformationValueCodecFieldCapture(&sealed) = func(v s15.OTDOACellInformation, options aper.DecodeState) (s15.OTDOACellInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeCaptureLPPaOTDOACellInformation(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s15.BridgeOTDOACellInformationValueCodecFieldCompare(&sealed) = func(v s15.OTDOACellInformation, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s15.BridgeCompareLPPaOTDOACellInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s15.BridgeOTDOACellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellInformation"
			return sealed
		}()
		return sealed
	}()

}

// OTDOACellsCodec binds the complete APER value type.
func OTDOACellsCodec() s16.OTDOACellsValueCodec {
	return OTDOAInformationResponseIEs().OTDOACells().Codec()
}

// OTDOAInformationTypeCodec binds the complete APER value type.
func OTDOAInformationTypeCodec() s08.OTDOAInformationTypeValueCodec {
	return OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OTDOAInformationRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 9:
		if v.rowOTDOAInformationTypeGroup != nil {
			return v.rowOTDOAInformationTypeGroup, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OTDOAInformationResponseIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if v.rowOTDOACells != nil {
			return v.rowOTDOACells, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	case 18:
		if v.rowAddOTDOACells != nil {
			return v.rowAddOTDOACells, true
		}
	}
	return nil, false
}

func BridgeMBSFNsubframeConfigurationCompleteFieldPerPadding(v *MBSFNsubframeConfigurationComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReceived(v *MBSFNsubframeConfigurationComplete) *bool {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReceivedBytes(v *MBSFNsubframeConfigurationComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReplay(v *MBSFNsubframeConfigurationComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationCompleteFieldStream(v *MBSFNsubframeConfigurationComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeMBSFNsubframeConfigurationCompleteFieldWithoutReplay(v *MBSFNsubframeConfigurationComplete) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERBudget(v *MBSFNsubframeConfigurationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERChanged(v *MBSFNsubframeConfigurationComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERChangedValue(v *MBSFNsubframeConfigurationComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERFreshValue(v *MBSFNsubframeConfigurationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERLegacy(v *MBSFNsubframeConfigurationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERPlanned(v *MBSFNsubframeConfigurationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodUnmarshalAPERLegacy(v *MBSFNsubframeConfigurationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodUnmarshalAPERWithOptions(v *MBSFNsubframeConfigurationComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasuredResultsCompleteFieldPerPadding(v *MeasuredResultsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMeasuredResultsCompleteFieldReceived(v *MeasuredResultsComplete) *bool { return &v.received }
func BridgeMeasuredResultsCompleteFieldReceivedBytes(v *MeasuredResultsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasuredResultsCompleteFieldReplay(v *MeasuredResultsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsCompleteFieldStream(v *MeasuredResultsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasuredResultsCompleteFieldWithoutReplay(v *MeasuredResultsComplete) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERBudget(v *MeasuredResultsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERChanged(v *MeasuredResultsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERChangedValue(v *MeasuredResultsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERFreshValue(v *MeasuredResultsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERLegacy(v *MeasuredResultsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERPlanned(v *MeasuredResultsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodUnmarshalAPERLegacy(v *MeasuredResultsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasuredResultsCompleteMethodUnmarshalAPERWithOptions(v *MeasuredResultsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteFieldPerPadding(v *MeasurementQuantitiesComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMeasurementQuantitiesCompleteFieldReceived(v *MeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeMeasurementQuantitiesCompleteFieldReceivedBytes(v *MeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementQuantitiesCompleteFieldReplay(v *MeasurementQuantitiesComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesCompleteFieldStream(v *MeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesCompleteFieldWithoutReplay(v *MeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *MeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *MeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *MeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *MeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *MeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *MeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *MeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *MeasurementQuantitiesComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellInformationCompleteFieldPerPadding(v *OTDOACellInformationComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellInformationCompleteFieldReceived(v *OTDOACellInformationComplete) *bool {
	return &v.received
}
func BridgeOTDOACellInformationCompleteFieldReceivedBytes(v *OTDOACellInformationComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellInformationCompleteFieldReplay(v *OTDOACellInformationComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationCompleteFieldStream(v *OTDOACellInformationComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOACellInformationCompleteFieldWithoutReplay(v *OTDOACellInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERBudget(v *OTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERChanged(v *OTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERChangedValue(v *OTDOACellInformationComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERFreshValue(v *OTDOACellInformationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERLegacy(v *OTDOACellInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERPlanned(v *OTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodUnmarshalAPERLegacy(v *OTDOACellInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellInformationCompleteMethodUnmarshalAPERWithOptions(v *OTDOACellInformationComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellsCompleteFieldPerPadding(v *OTDOACellsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellsCompleteFieldReceived(v *OTDOACellsComplete) *bool { return &v.received }
func BridgeOTDOACellsCompleteFieldReceivedBytes(v *OTDOACellsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellsCompleteFieldReplay(v *OTDOACellsComplete) *aper.Snapshot { return &v.replay }
func BridgeOTDOACellsCompleteFieldStream(v *OTDOACellsComplete) *aper.WireSpan { return &v.stream }
func BridgeOTDOACellsCompleteFieldWithoutReplay(v *OTDOACellsComplete) *bool   { return &v.withoutReplay }
func BridgeOTDOACellsCompleteMethodMarshalAPERBudget(v *OTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERChanged(v *OTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERChangedValue(v *OTDOACellsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERFreshValue(v *OTDOACellsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERLegacy(v *OTDOACellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellsCompleteMethodMarshalAPERPlanned(v *OTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellsCompleteMethodUnmarshalAPERLegacy(v *OTDOACellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellsCompleteMethodUnmarshalAPERWithOptions(v *OTDOACellsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationRequestAPERValueFieldContext(v *OTDOAInformationRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestAPERValueFieldReceived(v *OTDOAInformationRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationRequestAPERValueFieldReplay(v *OTDOAInformationRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestAPERValueFieldWithoutReplay(v *OTDOAInformationRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestFieldExtCount(v *OTDOAInformationRequest) *int64 {
	return &v.extCount
}
func BridgeOTDOAInformationRequestFieldExtData(v *OTDOAInformationRequest) *[][]byte {
	return &v.extData
}
func BridgeOTDOAInformationRequestFieldExtOrigin(v *OTDOAInformationRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationRequestFieldExtPresent(v *OTDOAInformationRequest) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationRequestFieldExtWire(v *OTDOAInformationRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationRequestFieldPerExtPadding(v *OTDOAInformationRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationRequestFieldPerPadding(v *OTDOAInformationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationRequestFieldProtocolIEsIndef(v *OTDOAInformationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationRequestFieldReceived(v *OTDOAInformationRequest) *bool { return &v.received }
func BridgeOTDOAInformationRequestFieldReceivedBytes(v *OTDOAInformationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationRequestFieldReplay(v *OTDOAInformationRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestFieldStream(v *OTDOAInformationRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationRequestFieldWithoutReplay(v *OTDOAInformationRequest) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEFieldFieldReceived(v *OTDOAInformationRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationRequestIEFieldFieldReplay(v *OTDOAInformationRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestIEFieldFieldStream(v *OTDOAInformationRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationRequestIEFieldFieldWithoutReplay(v *OTDOAInformationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEFieldMethodMarshalAPERTo(v *OTDOAInformationRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationRequestIETableMethodInfoOTDOAInformationTypeGroup(v OTDOAInformationRequestIETable) s00.FieldInfo {
	return v.infoOTDOAInformationTypeGroup()
}
func BridgeOTDOAInformationRequestIEValueFieldId(v *OTDOAInformationRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationRequestIEValueFieldIsOpaque(v *OTDOAInformationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationRequestIEValueFieldOpaque(v *OTDOAInformationRequestIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationRequestIEValueFieldReceived(v *OTDOAInformationRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationRequestIEValueFieldReplay(v *OTDOAInformationRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestIEValueFieldRowOTDOAInformationTypeGroup(v *OTDOAInformationRequestIEValue) **s07.OTDOAInformationType {
	return &v.rowOTDOAInformationTypeGroup
}
func BridgeOTDOAInformationRequestIEValueFieldWithoutReplay(v *OTDOAInformationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureFraming(v OTDOAInformationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureSemantics(v OTDOAInformationRequestIEValue, a0 aper.SemanticCapture) OTDOAInformationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureSnapshot(v OTDOAInformationRequestIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationRequestIEValueMethodCompareSemantics(v OTDOAInformationRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodDecode(v OTDOAInformationRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOAInformationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodEncode(v OTDOAInformationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationRequestIEValueMethodEncodeFresh(v OTDOAInformationRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodMatchesID(v OTDOAInformationRequestIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodReason(v OTDOAInformationRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodRule(v OTDOAInformationRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v *OTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERChanged(v *OTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERChangedValue(v *OTDOAInformationRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERFreshValue(v *OTDOAInformationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERLegacy(v *OTDOAInformationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationRequestMethodMarshalAPERPlanned(v *OTDOAInformationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERTo(v *OTDOAInformationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERFrom(v *OTDOAInformationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERLegacy(v *OTDOAInformationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERWithOptions(v *OTDOAInformationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldCodec(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *s08.OTDOAInformationTypeValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldGet(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *func(*OTDOAInformationRequestIEValue) (*s07.OTDOAInformationType, bool) {
	return &v.get
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldInfo(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldInject(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *func(s07.OTDOAInformationType) OTDOAInformationRequestIEValue {
	return &v.inject
}
func BridgeOTDOAInformationRequestValueCodecFieldCapture(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, aper.DecodeState) (OTDOAInformationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationRequestValueCodecFieldCompare(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationRequestValueCodecFieldContext(v *OTDOAInformationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestValueCodecFieldDecode(v *OTDOAInformationRequestValueCodec) *func([]byte, aper.DecodeState) (OTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeOTDOAInformationRequestValueCodecFieldEncode(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationRequestValueCodecFieldPath(v *OTDOAInformationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationRequestValueCodecMethodEncodeBudget(v OTDOAInformationRequestValueCodec, a0 OTDOAInformationRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationRequestValueCodecMethodEncodeChanged(v OTDOAInformationRequestValueCodec, a0 OTDOAInformationRequest, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationResponseAPERValueFieldContext(v *OTDOAInformationResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseAPERValueFieldReceived(v *OTDOAInformationResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationResponseAPERValueFieldReplay(v *OTDOAInformationResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseAPERValueFieldWithoutReplay(v *OTDOAInformationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldCodec(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *s15.AddOTDOACellsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldGet(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *func(*OTDOAInformationResponseIEValue) (*s15.AddOTDOACells, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldInfo(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldInject(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *func(s15.AddOTDOACells) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldGet(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(*OTDOAInformationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInject(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseFieldExtCount(v *OTDOAInformationResponse) *int64 {
	return &v.extCount
}
func BridgeOTDOAInformationResponseFieldExtData(v *OTDOAInformationResponse) *[][]byte {
	return &v.extData
}
func BridgeOTDOAInformationResponseFieldExtOrigin(v *OTDOAInformationResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationResponseFieldExtPresent(v *OTDOAInformationResponse) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationResponseFieldExtWire(v *OTDOAInformationResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationResponseFieldPerExtPadding(v *OTDOAInformationResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationResponseFieldPerPadding(v *OTDOAInformationResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationResponseFieldProtocolIEsIndef(v *OTDOAInformationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationResponseFieldReceived(v *OTDOAInformationResponse) *bool {
	return &v.received
}
func BridgeOTDOAInformationResponseFieldReceivedBytes(v *OTDOAInformationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationResponseFieldReplay(v *OTDOAInformationResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseFieldStream(v *OTDOAInformationResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationResponseFieldWithoutReplay(v *OTDOAInformationResponse) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEFieldFieldReceived(v *OTDOAInformationResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationResponseIEFieldFieldReplay(v *OTDOAInformationResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseIEFieldFieldStream(v *OTDOAInformationResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationResponseIEFieldFieldWithoutReplay(v *OTDOAInformationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEFieldMethodMarshalAPERTo(v *OTDOAInformationResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationResponseIETableMethodInfoAddOTDOACells(v OTDOAInformationResponseIETable) s00.FieldInfo {
	return v.infoAddOTDOACells()
}
func BridgeOTDOAInformationResponseIETableMethodInfoCriticalityDiagnostics(v OTDOAInformationResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeOTDOAInformationResponseIETableMethodInfoOTDOACells(v OTDOAInformationResponseIETable) s00.FieldInfo {
	return v.infoOTDOACells()
}
func BridgeOTDOAInformationResponseIEValueFieldId(v *OTDOAInformationResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationResponseIEValueFieldIsOpaque(v *OTDOAInformationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationResponseIEValueFieldOpaque(v *OTDOAInformationResponseIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationResponseIEValueFieldReceived(v *OTDOAInformationResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationResponseIEValueFieldReplay(v *OTDOAInformationResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseIEValueFieldRowAddOTDOACells(v *OTDOAInformationResponseIEValue) **s15.AddOTDOACells {
	return &v.rowAddOTDOACells
}
func BridgeOTDOAInformationResponseIEValueFieldRowCriticalityDiagnostics(v *OTDOAInformationResponseIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeOTDOAInformationResponseIEValueFieldRowOTDOACells(v *OTDOAInformationResponseIEValue) **s16.OTDOACells {
	return &v.rowOTDOACells
}
func BridgeOTDOAInformationResponseIEValueFieldWithoutReplay(v *OTDOAInformationResponseIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureFraming(v OTDOAInformationResponseIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureSemantics(v OTDOAInformationResponseIEValue, a0 aper.SemanticCapture) OTDOAInformationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureSnapshot(v OTDOAInformationResponseIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationResponseIEValueMethodCompareSemantics(v OTDOAInformationResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodDecode(v OTDOAInformationResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOAInformationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodEncode(v OTDOAInformationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationResponseIEValueMethodEncodeFresh(v OTDOAInformationResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodMatchesID(v OTDOAInformationResponseIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodReason(v OTDOAInformationResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodRule(v OTDOAInformationResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v *OTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERChanged(v *OTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERChangedValue(v *OTDOAInformationResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERFreshValue(v *OTDOAInformationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERLegacy(v *OTDOAInformationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationResponseMethodMarshalAPERPlanned(v *OTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERTo(v *OTDOAInformationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERFrom(v *OTDOAInformationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERLegacy(v *OTDOAInformationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERWithOptions(v *OTDOAInformationResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldCodec(v *OTDOAInformationResponseOTDOACellsIEBinding) *s16.OTDOACellsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldGet(v *OTDOAInformationResponseOTDOACellsIEBinding) *func(*OTDOAInformationResponseIEValue) (*s16.OTDOACells, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldInfo(v *OTDOAInformationResponseOTDOACellsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldInject(v *OTDOAInformationResponseOTDOACellsIEBinding) *func(s16.OTDOACells) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseValueCodecFieldCapture(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, aper.DecodeState) (OTDOAInformationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationResponseValueCodecFieldCompare(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationResponseValueCodecFieldContext(v *OTDOAInformationResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseValueCodecFieldDecode(v *OTDOAInformationResponseValueCodec) *func([]byte, aper.DecodeState) (OTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeOTDOAInformationResponseValueCodecFieldEncode(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationResponseValueCodecFieldPath(v *OTDOAInformationResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationResponseValueCodecMethodEncodeBudget(v OTDOAInformationResponseValueCodec, a0 OTDOAInformationResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationResponseValueCodecMethodEncodeChanged(v OTDOAInformationResponseValueCodec, a0 OTDOAInformationResponse, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeCompleteFieldPerPadding(v *OTDOAInformationTypeComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOAInformationTypeCompleteFieldReceived(v *OTDOAInformationTypeComplete) *bool {
	return &v.received
}
func BridgeOTDOAInformationTypeCompleteFieldReceivedBytes(v *OTDOAInformationTypeComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationTypeCompleteFieldReplay(v *OTDOAInformationTypeComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeCompleteFieldStream(v *OTDOAInformationTypeComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeCompleteFieldWithoutReplay(v *OTDOAInformationTypeComplete) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERBudget(v *OTDOAInformationTypeComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERChanged(v *OTDOAInformationTypeComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERChangedValue(v *OTDOAInformationTypeComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERFreshValue(v *OTDOAInformationTypeComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERLegacy(v *OTDOAInformationTypeComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERPlanned(v *OTDOAInformationTypeComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodUnmarshalAPERLegacy(v *OTDOAInformationTypeComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationTypeCompleteMethodUnmarshalAPERWithOptions(v *OTDOAInformationTypeComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
