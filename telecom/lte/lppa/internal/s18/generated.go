// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s18 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s18

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// OTDOAInformationRequestIEContainer is the concrete ProtocolIEContainer[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEContainer []OTDOAInformationRequestIEField

// OTDOAInformationRequestIEField is the concrete ProtocolIEField[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         OTDOAInformationRequestIEValue

	received q4.CompletePadding
}

func (v OTDOAInformationRequestIEField) WithoutReplay() OTDOAInformationRequestIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOAInformationRequestIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationRequestIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationRequestIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationRequestIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero OTDOAInformationRequestIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// OTDOAInformationResponseIEContainer is the concrete ProtocolIEContainer[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEContainer []OTDOAInformationResponseIEField

// OTDOAInformationResponseIEField is the concrete ProtocolIEField[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         OTDOAInformationResponseIEValue

	received q4.CompletePadding
}

func (v OTDOAInformationResponseIEField) WithoutReplay() OTDOAInformationResponseIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *OTDOAInformationResponseIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationResponseIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *OTDOAInformationResponseIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationResponseIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero OTDOAInformationResponseIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEContainer(v *OTDOAInformationRequestIEContainer, s *q4.SemanticCapture) {
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
func BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(v *OTDOAInformationRequestIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(v *OTDOAInformationResponseIEContainer, s *q4.SemanticCapture) {
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
func BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(v *OTDOAInformationResponseIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}

// OTDOAInformationRequestOTDOAInformationTypeIEBinding is the concrete IEBinding[OTDOAInformationType, OTDOAInformationRequestIEValue].
type OTDOAInformationRequestOTDOAInformationTypeIEBinding struct {
	info   q5.FieldInfo
	codec  q9.OTDOAInformationTypeValueCodec
	inject func(q9.OTDOAInformationType,

	) OTDOAInformationRequestIEValue

	get func(*OTDOAInformationRequestIEValue,

	) (*q9.OTDOAInformationType,

		bool)
}

func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Info() q5.FieldInfo { return b.info }
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Codec() q9.OTDOAInformationTypeValueCodec {
	return b.codec
}
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) New(value q9.OTDOAInformationType,

) (OTDOAInformationRequestIEField, error) {
	if b.inject == nil {
		return OTDOAInformationRequestIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationRequestIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeOTDOAInformationTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationRequestIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationRequestIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationRequestOTDOAInformationTypeIEBinding) Get(field *OTDOAInformationRequestIEField) (*q9.OTDOAInformationType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseOTDOACellsIEBinding is the concrete IEBinding[OTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseOTDOACellsIEBinding struct {
	info   q5.FieldInfo
	codec  q10.OTDOACellsValueCodec
	inject func(q10.OTDOACells,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*q10.OTDOACells,

		bool)
}

func (b OTDOAInformationResponseOTDOACellsIEBinding) Info() q5.FieldInfo { return b.info }
func (b OTDOAInformationResponseOTDOACellsIEBinding) Codec() q10.OTDOACellsValueCodec {
	return b.codec
}
func (b OTDOAInformationResponseOTDOACellsIEBinding) New(value q10.OTDOACells,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeOTDOACellsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationResponseOTDOACellsIEBinding) Get(field *OTDOAInformationResponseIEField) (*q10.OTDOACells,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q11.CriticalityDiagnosticsValueCodec
	inject func(q11.CriticalityDiagnostics,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*q11.CriticalityDiagnostics,

		bool)
}

func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo { return b.info }
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Codec() q11.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) New(value q11.CriticalityDiagnostics,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q11.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationResponseCriticalityDiagnosticsIEBinding) Get(field *OTDOAInformationResponseIEField) (*q11.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationResponseAddOTDOACellsIEBinding is the concrete IEBinding[AddOTDOACells, OTDOAInformationResponseIEValue].
type OTDOAInformationResponseAddOTDOACellsIEBinding struct {
	info   q5.FieldInfo
	codec  q12.AddOTDOACellsValueCodec
	inject func(q12.AddOTDOACells,

	) OTDOAInformationResponseIEValue

	get func(*OTDOAInformationResponseIEValue,

	) (*q12.AddOTDOACells,

		bool)
}

func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Info() q5.FieldInfo { return b.info }
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Codec() q12.AddOTDOACellsValueCodec {
	return b.codec
}
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) New(value q12.AddOTDOACells,

) (OTDOAInformationResponseIEField, error) {
	if b.inject == nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q12.BridgeAddOTDOACellsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b OTDOAInformationResponseAddOTDOACellsIEBinding) Get(field *OTDOAInformationResponseIEField) (*q12.AddOTDOACells,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationRequestValueCodec is the concrete ValueCodec[OTDOAInformationRequest].
type OTDOAInformationRequestValueCodec struct {
	context q5.BridgeCodecContext
	capture func(OTDOAInformationRequest, q4.DecodeState,

	) (OTDOAInformationRequest, q4.Snapshot,

	)
	compare func(OTDOAInformationRequest, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (OTDOAInformationRequest,

		error)
	encode func(OTDOAInformationRequest,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationRequestValueCodec) New(value OTDOAInformationRequest,

) (OTDOAInformationRequestAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationRequestAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationRequestAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationRequestAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationRequestAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c OTDOAInformationRequestValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (OTDOAInformationRequestAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationRequestAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return OTDOAInformationRequestAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationRequestAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationRequestAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return OTDOAInformationRequestAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationRequestValueCodec) EncodeAPER(value OTDOAInformationRequestAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c OTDOAInformationRequestValueCodec) encodeBudget(value OTDOAInformationRequest,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationRequestValueCodec) encodeChanged(value OTDOAInformationRequest,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// OTDOAInformationResponseValueCodec is the concrete ValueCodec[OTDOAInformationResponse].
type OTDOAInformationResponseValueCodec struct {
	context q5.BridgeCodecContext
	capture func(OTDOAInformationResponse, q4.DecodeState,

	) (OTDOAInformationResponse, q4.Snapshot,

	)
	compare func(OTDOAInformationResponse, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (OTDOAInformationResponse,

		error)
	encode func(OTDOAInformationResponse,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationResponseValueCodec) New(value OTDOAInformationResponse,

) (OTDOAInformationResponseAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationResponseAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return OTDOAInformationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return OTDOAInformationResponseAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c OTDOAInformationResponseValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (OTDOAInformationResponseAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return OTDOAInformationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return OTDOAInformationResponseAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationResponseValueCodec) EncodeAPER(value OTDOAInformationResponseAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c OTDOAInformationResponseValueCodec) encodeBudget(value OTDOAInformationResponse,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationResponseValueCodec) encodeChanged(value OTDOAInformationResponse,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(fields OTDOAInformationRequestIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q13.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q13.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q13.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(fields OTDOAInformationResponseIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q13.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q13.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q13.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// oTDOAInformationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationRequestIEValue].
type OTDOAInformationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) OTDOAInformationRequestIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (OTDOAInformationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeOTDOAInformationRequestIEValueCaptureLPPaProtocolIEField(v *OTDOAInformationRequestIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEField(v *OTDOAInformationRequestIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q14.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// oTDOAInformationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[OTDOAInformationResponseIEValue].
type OTDOAInformationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) OTDOAInformationResponseIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (OTDOAInformationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeOTDOAInformationResponseIEValueCaptureLPPaProtocolIEField(v *OTDOAInformationResponseIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEField(v *OTDOAInformationResponseIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q14.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// OTDOAInformationRequestAPERValue is the concrete APERValue[OTDOAInformationRequest].
type OTDOAInformationRequestAPERValue struct {
	context q5.BridgeCodecContext
	Value   OTDOAInformationRequest

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationRequestAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v OTDOAInformationRequestAPERValue) WithoutReplay() OTDOAInformationRequestAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationResponseAPERValue is the concrete APERValue[OTDOAInformationResponse].
type OTDOAInformationResponseAPERValue struct {
	context q5.BridgeCodecContext
	Value   OTDOAInformationResponse

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationResponseAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v OTDOAInformationResponseAPERValue) WithoutReplay() OTDOAInformationResponseAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesComplete carries a complete MeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasurementQuantitiesComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q15.MeasurementQuantities
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *MeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q16.BridgeMarshalAPERMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MeasurementQuantities from APER format.
func (v *MeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasurementQuantities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantities")
	}
	value, err := BridgeUnmarshalAPERMeasurementQuantitiesFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantities")
	}
	padding, err := q4.CaptureFinalBits(bb, "MeasurementQuantities")
	if err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantities")
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
func BridgeUnmarshalAPERMeasurementQuantitiesFrom(bb *q4.BitBuffer) (q15.MeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPERMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMeasurementQuantitiesInto(v *q11.BridgeAsn1cAPERMeasurementQuantitiesListValue, bb *q4.BitBuffer) error {
	v.Value = make(q15.MeasurementQuantities, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q15.MeasurementQuantitiesItemIEValueProtocolIESingleContainer
			if err := q15.BridgeMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MeasuredResultsComplete carries a complete MeasuredResults encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MeasuredResultsComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q17.MeasuredResults
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *MeasuredResultsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q17.BridgeMarshalAPERMeasuredResultsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MeasuredResults from APER format.
func (v *MeasuredResultsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasuredResults with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasuredResultsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MeasuredResults")
	}
	value, err := BridgeUnmarshalAPERMeasuredResultsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "MeasuredResults")
	}
	padding, err := q4.CaptureFinalBits(bb, "MeasuredResults")
	if err != nil {
		return q7.WrapDecodePath(err, "MeasuredResults")
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
func BridgeUnmarshalAPERMeasuredResultsFrom(bb *q4.BitBuffer) (q17.MeasuredResults, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q17.BridgeAsn1cAPERMeasuredResultsListValue
	if err := BridgeUnmarshalAPERMeasuredResultsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMeasuredResultsInto(v *q17.BridgeAsn1cAPERMeasuredResultsListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q17.MeasuredResults, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q17.MeasuredResultsValue
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q17.BridgeMeasuredResultsValueMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MBSFNsubframeConfigurationComplete carries a complete MBSFNsubframeConfiguration encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type MBSFNsubframeConfigurationComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q11.MBSFNsubframeConfiguration
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *MBSFNsubframeConfigurationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q16.BridgeMarshalAPERMBSFNsubframeConfigurationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes MBSFNsubframeConfiguration from APER format.
func (v *MBSFNsubframeConfigurationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MBSFNsubframeConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MBSFNsubframeConfigurationComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	value, err := q18.BridgeUnmarshalAPERMBSFNsubframeConfigurationFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfiguration")
	}
	padding, err := q4.CaptureFinalBits(bb, "MBSFNsubframeConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "MBSFNsubframeConfiguration")
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
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q10.OTDOACells
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *OTDOACellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q10.BridgeMarshalAPEROTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOACells from APER format.
func (v *OTDOACellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOACells")
	}
	value, err := BridgeUnmarshalAPEROTDOACellsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOACells")
	}
	padding, err := q4.CaptureFinalBits(bb, "OTDOACells")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOACells")
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
func BridgeUnmarshalAPEROTDOACellsFrom(bb *q4.BitBuffer) (q10.OTDOACells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q10.BridgeAsn1cAPEROTDOACellsListValue
	if err := BridgeUnmarshalAPEROTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOACellsInto(v *q10.BridgeAsn1cAPEROTDOACellsListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q10.OTDOACells, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q10.OTDOACellsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q10.BridgeOTDOACellsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// OTDOACellInformationComplete carries a complete OTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type OTDOACellInformationComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q12.OTDOACellInformation
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *OTDOACellInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q10.BridgeMarshalAPEROTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOACellInformation from APER format.
func (v *OTDOACellInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOACellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOACellInformationComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOACellInformation")
	}
	value, err := BridgeUnmarshalAPEROTDOACellInformationFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOACellInformation")
	}
	padding, err := q4.CaptureFinalBits(bb, "OTDOACellInformation")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOACellInformation")
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
func BridgeUnmarshalAPEROTDOACellInformationFrom(bb *q4.BitBuffer) (q12.OTDOACellInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q12.BridgeAsn1cAPEROTDOACellInformationListValue
	if err := BridgeUnmarshalAPEROTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOACellInformationInto(v *q12.BridgeAsn1cAPEROTDOACellInformationListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q12.OTDOACellInformation, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q12.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q12.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}
func BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsInto(v *q5.BridgeAsn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue, bb *q4.BitBuffer) error {
	v.Value = make(q5.PRSFrequencyHoppingConfigurationBandPositions, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound7, true)
			if err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q4.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MBSFNsubframeConfigurationComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "MBSFNsubframeConfigurationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MBSFNsubframeConfigurationComplete) WithoutReplay() MBSFNsubframeConfigurationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MBSFNsubframeConfigurationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasuredResultsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasuredResultsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasuredResultsComplete) WithoutReplay() MeasuredResultsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MeasuredResultsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementQuantitiesComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementQuantitiesComplete) WithoutReplay() MeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellInformationComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellInformationComplete) WithoutReplay() OTDOACellInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero OTDOACellInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOACellsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOACellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOACellsComplete) WithoutReplay() OTDOACellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero OTDOACellsComplete
	v.perPadding = zero.perPadding
	return v
}
func (v *MBSFNsubframeConfigurationComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MBSFNsubframeConfigurationComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMBSFNsubframeConfigurationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *MBSFNsubframeConfigurationComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MBSFNsubframeConfigurationComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPERMBSFNsubframeConfigurationTo(value.Value, bb, fresh); err != nil {
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
func (v *MeasuredResultsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MeasuredResultsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MeasuredResultsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasuredResultsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MeasuredResultsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MeasuredResultsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MeasuredResultsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MeasuredResultsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MeasuredResultsComplete")
}
func (v *MeasuredResultsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasuredResultsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasuredResultsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *MeasuredResultsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasuredResultsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q17.BridgeMarshalAPERMeasuredResultsTo(value.Value, bb, fresh); err != nil {
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
func (v *MeasurementQuantitiesComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MeasurementQuantitiesComplete")
}
func (v *MeasurementQuantitiesComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasurementQuantitiesComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasurementQuantitiesComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *MeasurementQuantitiesComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasurementQuantitiesComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPERMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
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
func (v *OTDOACellInformationComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "OTDOACellInformationComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "OTDOACellInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "OTDOACellInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "OTDOACellInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "OTDOACellInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "OTDOACellInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "OTDOACellInformationComplete")
}
func (v *OTDOACellInformationComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellInformationComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellInformationComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *OTDOACellInformationComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellInformationComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q10.BridgeMarshalAPEROTDOACellInformationTo(value.Value, bb, fresh); err != nil {
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
func (v *OTDOACellsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "OTDOACellsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "OTDOACellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOACellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "OTDOACellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "OTDOACellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "OTDOACellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "OTDOACellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "OTDOACellsComplete")
}
func (v *OTDOACellsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOACellsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOACellsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *OTDOACellsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOACellsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q10.BridgeMarshalAPEROTDOACellsTo(value.Value, bb, fresh); err != nil {
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
func (v *MBSFNsubframeConfigurationComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MBSFNsubframeConfigurationComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MBSFNsubframeConfigurationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMBSFNsubframeConfigurationComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MBSFNsubframeConfigurationComplete{}
		return report, q4.OperationError(err, "MBSFNsubframeConfigurationComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MBSFNsubframeConfigurationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasuredResultsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MeasuredResultsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MeasuredResultsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasuredResultsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MeasuredResultsComplete{}
		return report, q4.OperationError(err, "MeasuredResultsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MeasuredResultsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MeasurementQuantitiesComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MeasurementQuantitiesComplete{}
		return report, q4.OperationError(err, "MeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MeasurementQuantitiesComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellInformationComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "OTDOACellInformationComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellInformationComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellInformationComplete{}
		return report, q4.OperationError(err, "OTDOACellInformationComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "OTDOACellInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOACellsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "OTDOACellsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded OTDOACellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOACellsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOACellsComplete{}
		return report, q4.OperationError(err, "OTDOACellsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "OTDOACellsComplete")
}

// MarshalAPERMeasurementQuantities encodes a complete named list.
func MarshalAPERMeasurementQuantities(v MeasurementQuantitiesComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMeasuredResults encodes a complete named list.
func MarshalAPERMeasuredResults(v MeasuredResultsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERMBSFNsubframeConfiguration encodes a complete named list.
func MarshalAPERMBSFNsubframeConfiguration(v MBSFNsubframeConfigurationComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEROTDOACells encodes a complete named list.
func MarshalAPEROTDOACells(v OTDOACellsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEROTDOACellInformation encodes a complete named list.
func MarshalAPEROTDOACellInformation(v OTDOACellInformationComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERMeasurementQuantities decodes a complete named list.
func UnmarshalAPERMeasurementQuantities(data []byte, options ...q4.DecodeOption) (MeasurementQuantitiesComplete, q4.DecodeReport, error) {
	var v MeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMeasuredResults decodes a complete named list.
func UnmarshalAPERMeasuredResults(data []byte, options ...q4.DecodeOption) (MeasuredResultsComplete, q4.DecodeReport, error) {
	var v MeasuredResultsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERMBSFNsubframeConfiguration decodes a complete named list.
func UnmarshalAPERMBSFNsubframeConfiguration(data []byte, options ...q4.DecodeOption) (MBSFNsubframeConfigurationComplete, q4.DecodeReport, error) {
	var v MBSFNsubframeConfigurationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEROTDOACells decodes a complete named list.
func UnmarshalAPEROTDOACells(data []byte, options ...q4.DecodeOption) (OTDOACellsComplete, q4.DecodeReport, error) {
	var v OTDOACellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEROTDOACellInformation decodes a complete named list.
func UnmarshalAPEROTDOACellInformation(data []byte, options ...q4.DecodeOption) (OTDOACellInformationComplete, q4.DecodeReport, error) {
	var v OTDOACellInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// OTDOAInformationRequest represents the ASN.1 type OTDOAInformationRequest (SEQUENCE).
type OTDOAInformationRequest struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      OTDOAInformationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// OTDOAInformationResponse represents the ASN.1 type OTDOAInformationResponse (SEQUENCE).
type OTDOAInformationResponse struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      OTDOAInformationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                `asn1:"-" json:"-"`
	extCount         int64                               `asn1:"-" json:"-"`
	extPresent       []bool                              `asn1:"-" json:"-"`
	extData          [][]byte                            `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes OTDOAInformationRequest to APER format.
func (v *OTDOAInformationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationRequest) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q19.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes OTDOAInformationRequest from APER format.
func (v *OTDOAInformationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationRequest) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	padding, err := q4.CaptureFinalBits(bb, "OTDOAInformationRequest")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationRequest) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationRequest{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(OTDOAInformationRequestIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OTDOAInformationRequestIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q9.OTDOAInformationType
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *OTDOAInformationTypeComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q16.BridgeMarshalAPEROTDOAInformationTypeTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes OTDOAInformationType from APER format.
func (v *OTDOAInformationTypeComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationTypeComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationType")
	}
	value, err := BridgeUnmarshalAPEROTDOAInformationTypeFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationType")
	}
	padding, err := q4.CaptureFinalBits(bb, "OTDOAInformationType")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationType")
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
func BridgeUnmarshalAPEROTDOAInformationTypeFrom(bb *q4.BitBuffer) (q9.OTDOAInformationType, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPEROTDOAInformationTypeListValue
	if err := BridgeUnmarshalAPEROTDOAInformationTypeInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEROTDOAInformationTypeInto(v *q11.BridgeAsn1cAPEROTDOAInformationTypeListValue, bb *q4.BitBuffer) error {
	v.Value = make(q9.OTDOAInformationType, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q9.OTDOAInformationTypeIEValueProtocolIESingleContainer
			if err := q9.BridgeOTDOAInformationTypeIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes OTDOAInformationResponse to APER format.
func (v *OTDOAInformationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationResponse) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q19.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes OTDOAInformationResponse from APER format.
func (v *OTDOAInformationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationResponse) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	padding, err := q4.CaptureFinalBits(bb, "OTDOAInformationResponse")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationResponse) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationResponse{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(OTDOAInformationResponseIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem OTDOAInformationResponseIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
func (v *OTDOAInformationRequest) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationRequest) WithoutReplay() OTDOAInformationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero OTDOAInformationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOAInformationResponse) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationResponse) WithoutReplay() OTDOAInformationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero OTDOAInformationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *OTDOAInformationTypeComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q19.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationTypeComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationTypeComplete) WithoutReplay() OTDOAInformationTypeComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero OTDOAInformationTypeComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationRequest) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationResponse) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *OTDOAInformationRequest) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationRequest")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "OTDOAInformationRequest")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "OTDOAInformationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "OTDOAInformationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "OTDOAInformationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "OTDOAInformationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "OTDOAInformationRequest")
}
func (v *OTDOAInformationRequest) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationRequest) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationRequest) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *OTDOAInformationRequest) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationRequest) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *OTDOAInformationResponse) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationResponse")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "OTDOAInformationResponse")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "OTDOAInformationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "OTDOAInformationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "OTDOAInformationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "OTDOAInformationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "OTDOAInformationResponse")
}
func (v *OTDOAInformationResponse) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationResponse) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationResponse) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *OTDOAInformationResponse) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationResponse) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *OTDOAInformationTypeComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationTypeComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "OTDOAInformationTypeComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationTypeComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "OTDOAInformationTypeComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "OTDOAInformationTypeComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "OTDOAInformationTypeComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "OTDOAInformationTypeComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "OTDOAInformationTypeComplete")
}
func (v *OTDOAInformationTypeComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationTypeComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationTypeComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *OTDOAInformationTypeComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationTypeComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPEROTDOAInformationTypeTo(value.Value, bb, fresh); err != nil {
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
func (v *OTDOAInformationRequest) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationRequest")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationRequest(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationRequest{}
		return report, q4.OperationError(err, "OTDOAInformationRequest")
	}
	*v = decoded
	return report, q4.OperationError(nil, "OTDOAInformationRequest")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOAInformationResponse) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationResponse")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationResponse(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationResponse{}
		return report, q4.OperationError(err, "OTDOAInformationResponse")
	}
	*v = decoded
	return report, q4.OperationError(nil, "OTDOAInformationResponse")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *OTDOAInformationTypeComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "OTDOAInformationTypeComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationTypeComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationTypeComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationTypeComplete{}
		return report, q4.OperationError(err, "OTDOAInformationTypeComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "OTDOAInformationTypeComplete")
}

// MarshalAPEROTDOAInformationType encodes a complete named list.
func MarshalAPEROTDOAInformationType(v OTDOAInformationTypeComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPEROTDOAInformationType decodes a complete named list.
func UnmarshalAPEROTDOAInformationType(data []byte, options ...q4.DecodeOption) (OTDOAInformationTypeComplete, q4.DecodeReport, error) {
	var v OTDOAInformationTypeComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}
func BridgeCaptureLPPaMBSFNsubframeConfigurationComplete(v *MBSFNsubframeConfigurationComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q11.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMBSFNsubframeConfigurationComplete(v *MBSFNsubframeConfigurationComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q20.BridgeCompareLPPaMBSFNsubframeConfiguration(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasuredResultsComplete(v *MeasuredResultsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q17.BridgeCaptureLPPaMeasuredResults(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasuredResultsComplete(v *MeasuredResultsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q17.BridgeCompareLPPaMeasuredResults(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasurementQuantitiesComplete(v *MeasurementQuantitiesComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q16.BridgeCaptureLPPaMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasurementQuantitiesComplete(v *MeasurementQuantitiesComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q16.BridgeCompareLPPaMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellInformationComplete(v *OTDOACellInformationComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q12.BridgeCaptureLPPaOTDOACellInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellInformationComplete(v *OTDOACellInformationComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaOTDOACellInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOACellsComplete(v *OTDOACellsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q10.BridgeCaptureLPPaOTDOACells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOACellsComplete(v *OTDOACellsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q10.BridgeCompareLPPaOTDOACells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationRequest(v *OTDOAInformationRequest, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaOTDOAInformationRequest(v *OTDOAInformationRequest, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationRequestIEValue(v *OTDOAInformationRequestIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(9):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeGroup == nil)
				if v.rowOTDOAInformationTypeGroup != nil {
					q21.BridgeCaptureLPPaOTDOAInformationType(v.rowOTDOAInformationTypeGroup, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationRequestIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v OTDOAInformationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationRequestIEValue) captureSemantics(s q4.SemanticCapture) OTDOAInformationRequestIEValue {
	BridgeCaptureLPPaOTDOAInformationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationRequestIEValue(v *OTDOAInformationRequestIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(9):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeGroup == nil)
				if v.rowOTDOAInformationTypeGroup != nil {
					q21.BridgeCompareLPPaOTDOAInformationType(v.rowOTDOAInformationTypeGroup, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationRequestIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationRequestIEValue(&v, &s)
	return s
}
func (v OTDOAInformationRequestIEValue) WithoutReplay() OTDOAInformationRequestIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationResponse(v *OTDOAInformationResponse, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaOTDOAInformationResponse(v *OTDOAInformationResponse, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeOTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationResponseIEValue(v *OTDOAInformationResponseIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOACells == nil)
				if v.rowOTDOACells != nil {
					q10.BridgeCaptureLPPaOTDOACells(v.rowOTDOACells, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q11.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowAddOTDOACells == nil)
				if v.rowAddOTDOACells != nil {
					q12.BridgeCaptureLPPaAddOTDOACells(v.rowAddOTDOACells, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationResponseIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v OTDOAInformationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationResponseIEValue) captureSemantics(s q4.SemanticCapture) OTDOAInformationResponseIEValue {
	BridgeCaptureLPPaOTDOAInformationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationResponseIEValue(v *OTDOAInformationResponseIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOACells == nil)
				if v.rowOTDOACells != nil {
					q10.BridgeCompareLPPaOTDOACells(v.rowOTDOACells, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q11.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(18):
			{
				f := s.Begin()
				s.Bool(v.rowAddOTDOACells == nil)
				if v.rowAddOTDOACells != nil {
					q12.BridgeCompareLPPaAddOTDOACells(v.rowAddOTDOACells, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationResponseIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationResponseIEValue(&v, &s)
	return s
}
func (v OTDOAInformationResponseIEValue) WithoutReplay() OTDOAInformationResponseIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationTypeComplete(v *OTDOAInformationTypeComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q21.BridgeCaptureLPPaOTDOAInformationType(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationTypeComplete(v *OTDOAInformationTypeComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q21.BridgeCompareLPPaOTDOAInformationType(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

type OTDOAInformationRequestIEValue struct {
	id                           q5.ProtocolIEID
	withoutReplay                bool
	received                     q4.WireSpan
	replay                       q4.Snapshot
	opaque                       *q4.OpaqueOpenType
	isOpaque                     bool
	rowOTDOAInformationTypeGroup *q9.OTDOAInformationType
}

func (v OTDOAInformationRequestIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(9):
		return v.rowOTDOAInformationTypeGroup != nil
	default:
		return false
	}
}
func (v *OTDOAInformationRequestIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationRequestIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs"}}
}
func (OTDOAInformationRequestIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(9):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *OTDOAInformationRequestIEValue) AsOTDOAInformationTypeGroup() (*q9.OTDOAInformationType, bool) {
	if v == nil || v.id != q5.ProtocolIEID(9) || v.rowOTDOAInformationTypeGroup == nil {
		return nil, false
	}
	return v.rowOTDOAInformationTypeGroup, true
}
func (v OTDOAInformationRequestIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (OTDOAInformationRequestIEValue, error) {
	out := OTDOAInformationRequestIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 9:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(9):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPEROTDOAInformationTypeFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "OTDOAInformationTypeGroup:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := OTDOAInformationTypeComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOAInformationTypeGroup = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationRequestIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(9):
		if v.rowOTDOAInformationTypeGroup == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationRequest-IEs.id-OTDOA-Information-Type-Group:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, q6.Errorf("%s id %d has no value", "OTDOAInformationRequestIEValue:", v.id)
	}
}

type OTDOAInformationResponseIEValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowOTDOACells             *q10.OTDOACells
	rowCriticalityDiagnostics *q11.CriticalityDiagnostics
	rowAddOTDOACells          *q12.AddOTDOACells
}

func (v OTDOAInformationResponseIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(8):
		return v.rowOTDOACells != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	case q5.ProtocolIEID(18):
		return v.rowAddOTDOACells != nil
	default:
		return false
	}
}
func (v *OTDOAInformationResponseIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationResponseIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs"}}
}
func (OTDOAInformationResponseIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(8):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(18):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *OTDOAInformationResponseIEValue) AsOTDOACells() (*q10.OTDOACells, bool) {
	if v == nil || v.id != q5.ProtocolIEID(8) || v.rowOTDOACells == nil {
		return nil, false
	}
	return v.rowOTDOACells, true
}
func (v *OTDOAInformationResponseIEValue) AsCriticalityDiagnostics() (*q11.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v *OTDOAInformationResponseIEValue) AsAddOTDOACells() (*q12.AddOTDOACells, bool) {
	if v == nil || v.id != q5.ProtocolIEID(18) || v.rowAddOTDOACells == nil {
		return nil, false
	}
	return v.rowAddOTDOACells, true
}
func (v OTDOAInformationResponseIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (OTDOAInformationResponseIEValue, error) {
	out := OTDOAInformationResponseIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 8, 1, 18:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(8):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPEROTDOACellsFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "OTDOACells:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := OTDOACellsComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOACells = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q11.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q11.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q11.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q11.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q11.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(18):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := q18.BridgeUnmarshalAPERAddOTDOACellsFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "AddOTDOACells:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() q18.AddOTDOACellsComplete {
			sealed := q18.AddOTDOACellsComplete{Value: list}
			*q18.BridgeAddOTDOACellsCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAddOTDOACells = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationResponseIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(8):
		if v.rowOTDOACells == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-OTDOACells:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q11.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(18):
		if v.rowAddOTDOACells == nil {
			return nil, q6.Errorf("%s missing value", "OTDOAInformationResponse-IEs.id-AddOTDOACells:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := q18.AddOTDOACellsComplete{Value: *v.rowAddOTDOACells}
		candidate, err := q18.BridgeAddOTDOACellsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "OTDOAInformationResponseIEValue:", v.id)
	}
}

type OTDOAInformationRequestIETable struct{}

func OTDOAInformationRequestIEs() OTDOAInformationRequestIETable {
	return OTDOAInformationRequestIETable{}
}
func (OTDOAInformationRequestIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs"}
		return sealed
	}()
}
func (OTDOAInformationRequestIETable) infoOTDOAInformationTypeGroup() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationRequestIEs().ID(), ID: q5.ProtocolIEID(9), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationType"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationRequest-IEs", Row: "id-OTDOA-Information-Type-Group"}}}
}
func (t OTDOAInformationRequestIETable) OTDOAInformationTypeGroup() OTDOAInformationRequestOTDOAInformationTypeIEBinding {
	return OTDOAInformationRequestOTDOAInformationTypeIEBinding{info: t.infoOTDOAInformationTypeGroup(), codec: func() q9.OTDOAInformationTypeValueCodec {
		sealed := q9.OTDOAInformationTypeValueCodec{}
		*q9.BridgeOTDOAInformationTypeValueCodecFieldPath(&sealed) = "OTDOAInformationType"
		*q9.BridgeOTDOAInformationTypeValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.OTDOAInformationType, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.OTDOAInformationType
				return empty, err
			}
			var zero OTDOAInformationRequestIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(9), raw)
			if err != nil {
				var empty q9.OTDOAInformationType
				return empty, err
			}
			value, ok := decoded.AsOTDOAInformationTypeGroup()
			if !ok {
				var empty q9.OTDOAInformationType
				return empty, q6.Errorf("binding OTDOAInformationRequest-IEs.id-OTDOA-Information-Type-Group: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeOTDOAInformationTypeValueCodecFieldEncode(&sealed) = func(value q9.OTDOAInformationType, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationRequestIEValue{id: q5.ProtocolIEID(9), rowOTDOAInformationTypeGroup: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeOTDOAInformationTypeValueCodecFieldCapture(&sealed) = func(v q9.OTDOAInformationType, options q4.DecodeState) (q9.OTDOAInformationType, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q21.BridgeCaptureLPPaOTDOAInformationType(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q9.BridgeOTDOAInformationTypeValueCodecFieldCompare(&sealed) = func(v q9.OTDOAInformationType, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q21.BridgeCompareLPPaOTDOAInformationType(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeOTDOAInformationTypeValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationType"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.OTDOAInformationType) OTDOAInformationRequestIEValue {
			return OTDOAInformationRequestIEValue{id: q5.ProtocolIEID(9), rowOTDOAInformationTypeGroup: &value}
		}, get: func(value *OTDOAInformationRequestIEValue) (*q9.OTDOAInformationType, bool) {
			return value.AsOTDOAInformationTypeGroup()
		}}
}
func (t OTDOAInformationRequestIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (OTDOAInformationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationRequestIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(9):
		return OTDOAInformationRequestIEField{}, q4.OperationError(q6.Errorf("known IE id-OTDOA-Information-Type-Group requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return OTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationRequestIEField{}, q4.OperationError(err, "Opaque")
		}
		return OTDOAInformationRequestIEField{Id: id, Criticality: criticality, Value: OTDOAInformationRequestIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationResponseIETable struct{}

func OTDOAInformationResponseIEs() OTDOAInformationResponseIETable {
	return OTDOAInformationResponseIETable{}
}
func (OTDOAInformationResponseIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs"}
		return sealed
	}()
}
func (OTDOAInformationResponseIETable) infoOTDOACells() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: q5.ProtocolIEID(8), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-OTDOACells"}}}
}
func (t OTDOAInformationResponseIETable) OTDOACells() OTDOAInformationResponseOTDOACellsIEBinding {
	return OTDOAInformationResponseOTDOACellsIEBinding{info: t.infoOTDOACells(), codec: func() q10.OTDOACellsValueCodec {
		sealed := q10.OTDOACellsValueCodec{}
		*q10.BridgeOTDOACellsValueCodecFieldPath(&sealed) = "OTDOACells"
		*q10.BridgeOTDOACellsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.OTDOACells, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.OTDOACells
				return empty, err
			}
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(8), raw)
			if err != nil {
				var empty q10.OTDOACells
				return empty, err
			}
			value, ok := decoded.AsOTDOACells()
			if !ok {
				var empty q10.OTDOACells
				return empty, q6.Errorf("binding OTDOAInformationResponse-IEs.id-OTDOACells: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeOTDOACellsValueCodecFieldEncode(&sealed) = func(value q10.OTDOACells, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(8), rowOTDOACells: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeOTDOACellsValueCodecFieldCapture(&sealed) = func(v q10.OTDOACells, options q4.DecodeState) (q10.OTDOACells, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q10.BridgeCaptureLPPaOTDOACells(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*q10.BridgeOTDOACellsValueCodecFieldCompare(&sealed) = func(v q10.OTDOACells, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q10.BridgeCompareLPPaOTDOACells(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeOTDOACellsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACells"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.OTDOACells) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(8), rowOTDOACells: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*q10.OTDOACells, bool) { return value.AsOTDOACells() }}
}
func (OTDOAInformationResponseIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t OTDOAInformationResponseIETable) CriticalityDiagnostics() OTDOAInformationResponseCriticalityDiagnosticsIEBinding {
	return OTDOAInformationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q11.CriticalityDiagnosticsValueCodec {
		sealed := q11.CriticalityDiagnosticsValueCodec{}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q11.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q11.CriticalityDiagnostics
				return empty, err
			}
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q11.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q11.CriticalityDiagnostics
				return empty, q6.Errorf("binding OTDOAInformationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q11.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q11.CriticalityDiagnostics, options q4.DecodeState) (q11.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q11.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q11.CriticalityDiagnostics) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*q11.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (OTDOAInformationResponseIETable) infoAddOTDOACells() q5.FieldInfo {
	return q5.FieldInfo{Table: OTDOAInformationResponseIEs().ID(), ID: q5.ProtocolIEID(18), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "AddOTDOACells"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationResponse-IEs", Row: "id-AddOTDOACells"}}}
}
func (t OTDOAInformationResponseIETable) AddOTDOACells() OTDOAInformationResponseAddOTDOACellsIEBinding {
	return OTDOAInformationResponseAddOTDOACellsIEBinding{info: t.infoAddOTDOACells(), codec: func() q12.AddOTDOACellsValueCodec {
		sealed := q12.AddOTDOACellsValueCodec{}
		*q12.BridgeAddOTDOACellsValueCodecFieldPath(&sealed) = "AddOTDOACells"
		*q12.BridgeAddOTDOACellsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q12.AddOTDOACells, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q12.AddOTDOACells
				return empty, err
			}
			var zero OTDOAInformationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(18), raw)
			if err != nil {
				var empty q12.AddOTDOACells
				return empty, err
			}
			value, ok := decoded.AsAddOTDOACells()
			if !ok {
				var empty q12.AddOTDOACells
				return empty, q6.Errorf("binding OTDOAInformationResponse-IEs.id-AddOTDOACells: no selected value")
			}
			return *value, nil
		}
		*q12.BridgeAddOTDOACellsValueCodecFieldEncode(&sealed) = func(value q12.AddOTDOACells, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(18), rowAddOTDOACells: &value}).encodeFresh(fresh, budget)
		}
		*q12.BridgeAddOTDOACellsValueCodecFieldCapture(&sealed) = func(v q12.AddOTDOACells, options q4.DecodeState) (q12.AddOTDOACells, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaAddOTDOACells(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q12.BridgeAddOTDOACellsValueCodecFieldCompare(&sealed) = func(v q12.AddOTDOACells, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaAddOTDOACells(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q12.BridgeAddOTDOACellsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACells"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q12.AddOTDOACells) OTDOAInformationResponseIEValue {
			return OTDOAInformationResponseIEValue{id: q5.ProtocolIEID(18), rowAddOTDOACells: &value}
		}, get: func(value *OTDOAInformationResponseIEValue) (*q12.AddOTDOACells, bool) {
			return value.AsAddOTDOACells()
		}}
}
func (t OTDOAInformationResponseIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (OTDOAInformationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(8):
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-OTDOACells requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(18):
		return OTDOAInformationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-AddOTDOACells requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		return OTDOAInformationResponseIEField{Id: id, Criticality: criticality, Value: OTDOAInformationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// AddOTDOACellsCodec binds the complete APER value type.
func AddOTDOACellsCodec() q12.AddOTDOACellsValueCodec {
	return OTDOAInformationResponseIEs().AddOTDOACells().Codec()
}

// MBSFNsubframeConfigurationCodec binds the complete source value type.
func MBSFNsubframeConfigurationCodec() q11.MBSFNsubframeConfigurationConcreteValueCodec {
	return func() q11.MBSFNsubframeConfigurationConcreteValueCodec {
		sealed := q11.MBSFNsubframeConfigurationConcreteValueCodec{}
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldPath(&sealed) = "MBSFNsubframeConfiguration"
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q11.MBSFNsubframeConfiguration, error) {
			var complete MBSFNsubframeConfigurationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q11.MBSFNsubframeConfiguration
				return zero, err
			}
			return complete.Value, nil
		}
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldEncode(&sealed) = func(value q11.MBSFNsubframeConfiguration, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := MBSFNsubframeConfigurationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCapture(&sealed) = func(v q11.MBSFNsubframeConfiguration, options q4.DecodeState) (q11.MBSFNsubframeConfiguration, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaMBSFNsubframeConfiguration(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldCompare(&sealed) = func(v q11.MBSFNsubframeConfiguration, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q20.BridgeCompareLPPaMBSFNsubframeConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q11.BridgeMBSFNsubframeConfigurationConcreteValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MBSFNsubframeConfiguration"
			return sealed
		}()
		return sealed
	}()

}

// MeasuredResultsCodec binds the complete source value type.
func MeasuredResultsCodec() q17.MeasuredResultsConcreteValueCodec {
	return func() q17.MeasuredResultsConcreteValueCodec {
		sealed := q17.MeasuredResultsConcreteValueCodec{}
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldPath(&sealed) = "MeasuredResults"
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q17.MeasuredResults, error) {
			var complete MeasuredResultsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q17.MeasuredResults
				return zero, err
			}
			return complete.Value, nil
		}
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldEncode(&sealed) = func(value q17.MeasuredResults, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := MeasuredResultsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldCapture(&sealed) = func(v q17.MeasuredResults, options q4.DecodeState) (q17.MeasuredResults, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q17.BridgeCaptureLPPaMeasuredResults(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldCompare(&sealed) = func(v q17.MeasuredResults, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q17.BridgeCompareLPPaMeasuredResults(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q17.BridgeMeasuredResultsConcreteValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasuredResults"
			return sealed
		}()
		return sealed
	}()

}

// OTDOACellInformationCodec binds the complete source value type.
func OTDOACellInformationCodec() q12.OTDOACellInformationValueCodec {
	return func() q12.OTDOACellInformationValueCodec {
		sealed := q12.OTDOACellInformationValueCodec{}
		*q12.BridgeOTDOACellInformationValueCodecFieldPath(&sealed) = "OTDOACellInformation"
		*q12.BridgeOTDOACellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q12.OTDOACellInformation, error) {
			var complete OTDOACellInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q12.OTDOACellInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*q12.BridgeOTDOACellInformationValueCodecFieldEncode(&sealed) = func(value q12.OTDOACellInformation, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := OTDOACellInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q12.BridgeOTDOACellInformationValueCodecFieldCapture(&sealed) = func(v q12.OTDOACellInformation, options q4.DecodeState) (q12.OTDOACellInformation, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaOTDOACellInformation(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q12.BridgeOTDOACellInformationValueCodecFieldCompare(&sealed) = func(v q12.OTDOACellInformation, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaOTDOACellInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q12.BridgeOTDOACellInformationValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOACellInformation"
			return sealed
		}()
		return sealed
	}()

}

// OTDOACellsCodec binds the complete APER value type.
func OTDOACellsCodec() q10.OTDOACellsValueCodec {
	return OTDOAInformationResponseIEs().OTDOACells().Codec()
}

// OTDOAInformationTypeCodec binds the complete APER value type.
func OTDOAInformationTypeCodec() q9.OTDOAInformationTypeValueCodec {
	return OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Codec()
}
func BridgeMBSFNsubframeConfigurationCompleteFieldPerPadding(v *MBSFNsubframeConfigurationComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReceived(v *MBSFNsubframeConfigurationComplete) *bool {
	return &v.received
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReceivedBytes(v *MBSFNsubframeConfigurationComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMBSFNsubframeConfigurationCompleteFieldReplay(v *MBSFNsubframeConfigurationComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeMBSFNsubframeConfigurationCompleteFieldStream(v *MBSFNsubframeConfigurationComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeMBSFNsubframeConfigurationCompleteFieldWithoutReplay(v *MBSFNsubframeConfigurationComplete) *bool {
	return &v.withoutReplay
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERBudget(v *MBSFNsubframeConfigurationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERChanged(v *MBSFNsubframeConfigurationComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERChangedValue(v *MBSFNsubframeConfigurationComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERFreshValue(v *MBSFNsubframeConfigurationComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERLegacy(v *MBSFNsubframeConfigurationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMBSFNsubframeConfigurationCompleteMethodMarshalAPERPlanned(v *MBSFNsubframeConfigurationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodUnmarshalAPERLegacy(v *MBSFNsubframeConfigurationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMBSFNsubframeConfigurationCompleteMethodUnmarshalAPERWithOptions(v *MBSFNsubframeConfigurationComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasuredResultsCompleteFieldPerPadding(v *MeasuredResultsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeMeasuredResultsCompleteFieldReceived(v *MeasuredResultsComplete) *bool { return &v.received }
func BridgeMeasuredResultsCompleteFieldReceivedBytes(v *MeasuredResultsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasuredResultsCompleteFieldReplay(v *MeasuredResultsComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsCompleteFieldStream(v *MeasuredResultsComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasuredResultsCompleteFieldWithoutReplay(v *MeasuredResultsComplete) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERBudget(v *MeasuredResultsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERChanged(v *MeasuredResultsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERChangedValue(v *MeasuredResultsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERFreshValue(v *MeasuredResultsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERLegacy(v *MeasuredResultsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasuredResultsCompleteMethodMarshalAPERPlanned(v *MeasuredResultsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasuredResultsCompleteMethodUnmarshalAPERLegacy(v *MeasuredResultsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasuredResultsCompleteMethodUnmarshalAPERWithOptions(v *MeasuredResultsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteFieldPerPadding(v *MeasurementQuantitiesComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeMeasurementQuantitiesCompleteFieldReceived(v *MeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeMeasurementQuantitiesCompleteFieldReceivedBytes(v *MeasurementQuantitiesComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementQuantitiesCompleteFieldReplay(v *MeasurementQuantitiesComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesCompleteFieldStream(v *MeasurementQuantitiesComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesCompleteFieldWithoutReplay(v *MeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *MeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *MeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *MeasurementQuantitiesComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *MeasurementQuantitiesComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *MeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *MeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *MeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *MeasurementQuantitiesComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellInformationCompleteFieldPerPadding(v *OTDOACellInformationComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellInformationCompleteFieldReceived(v *OTDOACellInformationComplete) *bool {
	return &v.received
}
func BridgeOTDOACellInformationCompleteFieldReceivedBytes(v *OTDOACellInformationComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellInformationCompleteFieldReplay(v *OTDOACellInformationComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOACellInformationCompleteFieldStream(v *OTDOACellInformationComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOACellInformationCompleteFieldWithoutReplay(v *OTDOACellInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERBudget(v *OTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERChanged(v *OTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERChangedValue(v *OTDOACellInformationComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERFreshValue(v *OTDOACellInformationComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERLegacy(v *OTDOACellInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellInformationCompleteMethodMarshalAPERPlanned(v *OTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellInformationCompleteMethodUnmarshalAPERLegacy(v *OTDOACellInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellInformationCompleteMethodUnmarshalAPERWithOptions(v *OTDOACellInformationComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOACellsCompleteFieldPerPadding(v *OTDOACellsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOACellsCompleteFieldReceived(v *OTDOACellsComplete) *bool { return &v.received }
func BridgeOTDOACellsCompleteFieldReceivedBytes(v *OTDOACellsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOACellsCompleteFieldReplay(v *OTDOACellsComplete) *q4.Snapshot { return &v.replay }
func BridgeOTDOACellsCompleteFieldStream(v *OTDOACellsComplete) *q4.WireSpan { return &v.stream }
func BridgeOTDOACellsCompleteFieldWithoutReplay(v *OTDOACellsComplete) *bool { return &v.withoutReplay }
func BridgeOTDOACellsCompleteMethodMarshalAPERBudget(v *OTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERChanged(v *OTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERChangedValue(v *OTDOACellsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERFreshValue(v *OTDOACellsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOACellsCompleteMethodMarshalAPERLegacy(v *OTDOACellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOACellsCompleteMethodMarshalAPERPlanned(v *OTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOACellsCompleteMethodUnmarshalAPERLegacy(v *OTDOACellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOACellsCompleteMethodUnmarshalAPERWithOptions(v *OTDOACellsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationRequestAPERValueFieldContext(v *OTDOAInformationRequestAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestAPERValueFieldReceived(v *OTDOAInformationRequestAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationRequestAPERValueFieldReplay(v *OTDOAInformationRequestAPERValue) *q4.Snapshot {
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
func BridgeOTDOAInformationRequestFieldExtOrigin(v *OTDOAInformationRequest) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationRequestFieldExtPresent(v *OTDOAInformationRequest) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationRequestFieldExtWire(v *OTDOAInformationRequest) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationRequestFieldPerExtPadding(v *OTDOAInformationRequest) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationRequestFieldPerPadding(v *OTDOAInformationRequest) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationRequestFieldProtocolIEsIndef(v *OTDOAInformationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationRequestFieldReceived(v *OTDOAInformationRequest) *bool { return &v.received }
func BridgeOTDOAInformationRequestFieldReceivedBytes(v *OTDOAInformationRequest) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationRequestFieldReplay(v *OTDOAInformationRequest) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestFieldStream(v *OTDOAInformationRequest) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationRequestFieldWithoutReplay(v *OTDOAInformationRequest) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEFieldFieldReceived(v *OTDOAInformationRequestIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationRequestIEFieldFieldReplay(v *OTDOAInformationRequestIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestIEFieldFieldStream(v *OTDOAInformationRequestIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationRequestIEFieldFieldWithoutReplay(v *OTDOAInformationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEFieldMethodMarshalAPERTo(v *OTDOAInformationRequestIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationRequestIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationRequestIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationRequestIETableMethodInfoOTDOAInformationTypeGroup(v OTDOAInformationRequestIETable) q5.FieldInfo {
	return v.infoOTDOAInformationTypeGroup()
}
func BridgeOTDOAInformationRequestIEValueFieldId(v *OTDOAInformationRequestIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationRequestIEValueFieldIsOpaque(v *OTDOAInformationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationRequestIEValueFieldOpaque(v *OTDOAInformationRequestIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationRequestIEValueFieldReceived(v *OTDOAInformationRequestIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationRequestIEValueFieldReplay(v *OTDOAInformationRequestIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationRequestIEValueFieldRowOTDOAInformationTypeGroup(v *OTDOAInformationRequestIEValue) **q9.OTDOAInformationType {
	return &v.rowOTDOAInformationTypeGroup
}
func BridgeOTDOAInformationRequestIEValueFieldWithoutReplay(v *OTDOAInformationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureFraming(v OTDOAInformationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureSemantics(v OTDOAInformationRequestIEValue, a0 q4.SemanticCapture) OTDOAInformationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodCaptureSnapshot(v OTDOAInformationRequestIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationRequestIEValueMethodCompareSemantics(v OTDOAInformationRequestIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodDecode(v OTDOAInformationRequestIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (OTDOAInformationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodEncode(v OTDOAInformationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationRequestIEValueMethodEncodeFresh(v OTDOAInformationRequestIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodMatchesID(v OTDOAInformationRequestIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationRequestIEValueMethodReason(v OTDOAInformationRequestIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationRequestIEValueMethodRule(v OTDOAInformationRequestIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v *OTDOAInformationRequest, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERChanged(v *OTDOAInformationRequest, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERChangedValue(v *OTDOAInformationRequest, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERFreshValue(v *OTDOAInformationRequest, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERLegacy(v *OTDOAInformationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationRequestMethodMarshalAPERPlanned(v *OTDOAInformationRequest, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationRequestMethodMarshalAPERTo(v *OTDOAInformationRequest, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERFrom(v *OTDOAInformationRequest, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERLegacy(v *OTDOAInformationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationRequestMethodUnmarshalAPERWithOptions(v *OTDOAInformationRequest, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldCodec(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *q9.OTDOAInformationTypeValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldGet(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *func(*OTDOAInformationRequestIEValue) (*q9.OTDOAInformationType, bool) {
	return &v.get
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldInfo(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationRequestOTDOAInformationTypeIEBindingFieldInject(v *OTDOAInformationRequestOTDOAInformationTypeIEBinding) *func(q9.OTDOAInformationType) OTDOAInformationRequestIEValue {
	return &v.inject
}
func BridgeOTDOAInformationRequestValueCodecFieldCapture(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, q4.DecodeState) (OTDOAInformationRequest, q4.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationRequestValueCodecFieldCompare(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationRequestValueCodecFieldContext(v *OTDOAInformationRequestValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestValueCodecFieldDecode(v *OTDOAInformationRequestValueCodec) *func([]byte, q4.DecodeState) (OTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeOTDOAInformationRequestValueCodecFieldEncode(v *OTDOAInformationRequestValueCodec) *func(OTDOAInformationRequest, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationRequestValueCodecFieldPath(v *OTDOAInformationRequestValueCodec) *q4.Path {
	return &v.path
}
func BridgeOTDOAInformationRequestValueCodecMethodEncodeBudget(v OTDOAInformationRequestValueCodec, a0 OTDOAInformationRequest, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationRequestValueCodecMethodEncodeChanged(v OTDOAInformationRequestValueCodec, a0 OTDOAInformationRequest, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationResponseAPERValueFieldContext(v *OTDOAInformationResponseAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseAPERValueFieldReceived(v *OTDOAInformationResponseAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationResponseAPERValueFieldReplay(v *OTDOAInformationResponseAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseAPERValueFieldWithoutReplay(v *OTDOAInformationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldCodec(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *q12.AddOTDOACellsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldGet(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *func(*OTDOAInformationResponseIEValue) (*q12.AddOTDOACells, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldInfo(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseAddOTDOACellsIEBindingFieldInject(v *OTDOAInformationResponseAddOTDOACellsIEBinding) *func(q12.AddOTDOACells) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *q11.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldGet(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(*OTDOAInformationResponseIEValue) (*q11.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseCriticalityDiagnosticsIEBindingFieldInject(v *OTDOAInformationResponseCriticalityDiagnosticsIEBinding) *func(q11.CriticalityDiagnostics) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseFieldExtCount(v *OTDOAInformationResponse) *int64 {
	return &v.extCount
}
func BridgeOTDOAInformationResponseFieldExtData(v *OTDOAInformationResponse) *[][]byte {
	return &v.extData
}
func BridgeOTDOAInformationResponseFieldExtOrigin(v *OTDOAInformationResponse) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationResponseFieldExtPresent(v *OTDOAInformationResponse) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationResponseFieldExtWire(v *OTDOAInformationResponse) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationResponseFieldPerExtPadding(v *OTDOAInformationResponse) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationResponseFieldPerPadding(v *OTDOAInformationResponse) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationResponseFieldProtocolIEsIndef(v *OTDOAInformationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeOTDOAInformationResponseFieldReceived(v *OTDOAInformationResponse) *bool {
	return &v.received
}
func BridgeOTDOAInformationResponseFieldReceivedBytes(v *OTDOAInformationResponse) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationResponseFieldReplay(v *OTDOAInformationResponse) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseFieldStream(v *OTDOAInformationResponse) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationResponseFieldWithoutReplay(v *OTDOAInformationResponse) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEFieldFieldReceived(v *OTDOAInformationResponseIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationResponseIEFieldFieldReplay(v *OTDOAInformationResponseIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseIEFieldFieldStream(v *OTDOAInformationResponseIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationResponseIEFieldFieldWithoutReplay(v *OTDOAInformationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEFieldMethodMarshalAPERTo(v *OTDOAInformationResponseIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationResponseIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationResponseIETableMethodInfoAddOTDOACells(v OTDOAInformationResponseIETable) q5.FieldInfo {
	return v.infoAddOTDOACells()
}
func BridgeOTDOAInformationResponseIETableMethodInfoCriticalityDiagnostics(v OTDOAInformationResponseIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeOTDOAInformationResponseIETableMethodInfoOTDOACells(v OTDOAInformationResponseIETable) q5.FieldInfo {
	return v.infoOTDOACells()
}
func BridgeOTDOAInformationResponseIEValueFieldId(v *OTDOAInformationResponseIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationResponseIEValueFieldIsOpaque(v *OTDOAInformationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationResponseIEValueFieldOpaque(v *OTDOAInformationResponseIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationResponseIEValueFieldReceived(v *OTDOAInformationResponseIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationResponseIEValueFieldReplay(v *OTDOAInformationResponseIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationResponseIEValueFieldRowAddOTDOACells(v *OTDOAInformationResponseIEValue) **q12.AddOTDOACells {
	return &v.rowAddOTDOACells
}
func BridgeOTDOAInformationResponseIEValueFieldRowCriticalityDiagnostics(v *OTDOAInformationResponseIEValue) **q11.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeOTDOAInformationResponseIEValueFieldRowOTDOACells(v *OTDOAInformationResponseIEValue) **q10.OTDOACells {
	return &v.rowOTDOACells
}
func BridgeOTDOAInformationResponseIEValueFieldWithoutReplay(v *OTDOAInformationResponseIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureFraming(v OTDOAInformationResponseIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureSemantics(v OTDOAInformationResponseIEValue, a0 q4.SemanticCapture) OTDOAInformationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodCaptureSnapshot(v OTDOAInformationResponseIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationResponseIEValueMethodCompareSemantics(v OTDOAInformationResponseIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodDecode(v OTDOAInformationResponseIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (OTDOAInformationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodEncode(v OTDOAInformationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationResponseIEValueMethodEncodeFresh(v OTDOAInformationResponseIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodMatchesID(v OTDOAInformationResponseIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationResponseIEValueMethodReason(v OTDOAInformationResponseIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationResponseIEValueMethodRule(v OTDOAInformationResponseIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v *OTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERChanged(v *OTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERChangedValue(v *OTDOAInformationResponse, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERFreshValue(v *OTDOAInformationResponse, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERLegacy(v *OTDOAInformationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationResponseMethodMarshalAPERPlanned(v *OTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationResponseMethodMarshalAPERTo(v *OTDOAInformationResponse, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERFrom(v *OTDOAInformationResponse, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERLegacy(v *OTDOAInformationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationResponseMethodUnmarshalAPERWithOptions(v *OTDOAInformationResponse, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldCodec(v *OTDOAInformationResponseOTDOACellsIEBinding) *q10.OTDOACellsValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldGet(v *OTDOAInformationResponseOTDOACellsIEBinding) *func(*OTDOAInformationResponseIEValue) (*q10.OTDOACells, bool) {
	return &v.get
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldInfo(v *OTDOAInformationResponseOTDOACellsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseOTDOACellsIEBindingFieldInject(v *OTDOAInformationResponseOTDOACellsIEBinding) *func(q10.OTDOACells) OTDOAInformationResponseIEValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseValueCodecFieldCapture(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, q4.DecodeState) (OTDOAInformationResponse, q4.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationResponseValueCodecFieldCompare(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationResponseValueCodecFieldContext(v *OTDOAInformationResponseValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseValueCodecFieldDecode(v *OTDOAInformationResponseValueCodec) *func([]byte, q4.DecodeState) (OTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeOTDOAInformationResponseValueCodecFieldEncode(v *OTDOAInformationResponseValueCodec) *func(OTDOAInformationResponse, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationResponseValueCodecFieldPath(v *OTDOAInformationResponseValueCodec) *q4.Path {
	return &v.path
}
func BridgeOTDOAInformationResponseValueCodecMethodEncodeBudget(v OTDOAInformationResponseValueCodec, a0 OTDOAInformationResponse, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationResponseValueCodecMethodEncodeChanged(v OTDOAInformationResponseValueCodec, a0 OTDOAInformationResponse, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeCompleteFieldPerPadding(v *OTDOAInformationTypeComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeOTDOAInformationTypeCompleteFieldReceived(v *OTDOAInformationTypeComplete) *bool {
	return &v.received
}
func BridgeOTDOAInformationTypeCompleteFieldReceivedBytes(v *OTDOAInformationTypeComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationTypeCompleteFieldReplay(v *OTDOAInformationTypeComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeCompleteFieldStream(v *OTDOAInformationTypeComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeCompleteFieldWithoutReplay(v *OTDOAInformationTypeComplete) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERBudget(v *OTDOAInformationTypeComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERChanged(v *OTDOAInformationTypeComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERChangedValue(v *OTDOAInformationTypeComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERFreshValue(v *OTDOAInformationTypeComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERLegacy(v *OTDOAInformationTypeComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationTypeCompleteMethodMarshalAPERPlanned(v *OTDOAInformationTypeComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationTypeCompleteMethodUnmarshalAPERLegacy(v *OTDOAInformationTypeComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationTypeCompleteMethodUnmarshalAPERWithOptions(v *OTDOAInformationTypeComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
