// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s48 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s48

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UEContextResumeRequestIEContainer is ProtocolIE-Container {{UEContextResumeRequestIEs}} of TS 36.413: a list of UEContextResumeRequestIEField values.
type UEContextResumeRequestIEContainer []UEContextResumeRequestIEField

// UEContextResumeRequestIEField is ProtocolIE-Field {{UEContextResumeRequestIEs}} of TS 36.413: an information element field.
type UEContextResumeRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextResumeRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEField) WithoutReplay() UEContextResumeRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextResumeRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextResumeRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextResumeRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeRequestIEField{}
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
	var zero UEContextResumeRequestIEValue

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

// UEContextResumeResponseIEContainer is ProtocolIE-Container {{UEContextResumeResponseIEs}} of TS 36.413: a list of UEContextResumeResponseIEField values.
type UEContextResumeResponseIEContainer []UEContextResumeResponseIEField

// UEContextResumeResponseIEField is ProtocolIE-Field {{UEContextResumeResponseIEs}} of TS 36.413: an information element field.
type UEContextResumeResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextResumeResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEField) WithoutReplay() UEContextResumeResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextResumeResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextResumeResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextResumeResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeResponseIEField{}
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
	var zero UEContextResumeResponseIEValue

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
func BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEContainer(v *UEContextResumeRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEContainer(v *UEContextResumeRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// X2TNLConfigurationInfoExtIEsExtContainer is ProtocolExtensionContainer {{X2TNLConfigurationInfo-ExtIEs}} of TS 36.413: a list of X2TNLConfigurationInfoExtIEsExtField values.
type X2TNLConfigurationInfoExtIEsExtContainer []X2TNLConfigurationInfoExtIEsExtField

// X2TNLConfigurationInfoExtIEsExtField is ProtocolExtensionField {{X2TNLConfigurationInfo-ExtIEs}} of TS 36.413: an extension field.
type X2TNLConfigurationInfoExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue X2TNLConfigurationInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v X2TNLConfigurationInfoExtIEsExtField) WithoutReplay() X2TNLConfigurationInfoExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *X2TNLConfigurationInfoExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *X2TNLConfigurationInfoExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *X2TNLConfigurationInfoExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2TNLConfigurationInfoExtIEsExtField{}
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
	var zero X2TNLConfigurationInfoExtIEsValue

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

// X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding binds ENBX2ExtTLAs to the X2TNLConfigurationInfo-ExtIEs object set of TS 36.413.
type X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding struct {
	info   s00.ExtensionInfo
	codec  s18.ENBX2ExtTLAsValueCodec
	inject func(s18.ENBX2ExtTLAs,

	) X2TNLConfigurationInfoExtIEsValue

	get func(*X2TNLConfigurationInfoExtIEsValue,

	) (*s18.ENBX2ExtTLAs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding) Codec() s18.ENBX2ExtTLAsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding) New(value s18.ENBX2ExtTLAs,

) (X2TNLConfigurationInfoExtIEsExtField, error) {
	if b.inject == nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeENBX2ExtTLAsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return X2TNLConfigurationInfoExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding) Get(field *X2TNLConfigurationInfoExtIEsExtField) (*s18.ENBX2ExtTLAs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding binds ENBIndirectX2TransportLayerAddresses to the X2TNLConfigurationInfo-ExtIEs object set of TS 36.413.
type X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.ENBIndirectX2TransportLayerAddressesValueCodec
	inject func(s00.ENBIndirectX2TransportLayerAddresses,

	) X2TNLConfigurationInfoExtIEsValue

	get func(*X2TNLConfigurationInfoExtIEsValue,

	) (*s00.ENBIndirectX2TransportLayerAddresses,

		bool)
}

// Info returns the source descriptor for this binding.
func (b X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding) Codec() s00.ENBIndirectX2TransportLayerAddressesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding) New(value s00.ENBIndirectX2TransportLayerAddresses,

) (X2TNLConfigurationInfoExtIEsExtField, error) {
	if b.inject == nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return X2TNLConfigurationInfoExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding) Get(field *X2TNLConfigurationInfoExtIEsExtField) (*s00.ENBIndirectX2TransportLayerAddresses,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// UEContextResumeRequestMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextResumeRequestIEs object set of TS 36.413.
type UEContextResumeRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextResumeRequestIEValue

	get func(*UEContextResumeRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextResumeRequestIEField, error) {
	if b.inject == nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeRequestMMEUES1APIDIEBinding) Get(field *UEContextResumeRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeRequestENBUES1APIDIEBinding binds ENBUES1APID to the UEContextResumeRequestIEs object set of TS 36.413.
type UEContextResumeRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextResumeRequestIEValue

	get func(*UEContextResumeRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextResumeRequestIEField, error) {
	if b.inject == nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeRequestENBUES1APIDIEBinding) Get(field *UEContextResumeRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding binds ERABFailedToResumeListResumeReq to the UEContextResumeRequestIEs object set of TS 36.413.
type UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ERABFailedToResumeListResumeReqValueCodec
	inject func(s18.ERABFailedToResumeListResumeReq,

	) UEContextResumeRequestIEValue

	get func(*UEContextResumeRequestIEValue,

	) (*s18.ERABFailedToResumeListResumeReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding) Codec() s18.ERABFailedToResumeListResumeReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding) New(value s18.ERABFailedToResumeListResumeReq,

) (UEContextResumeRequestIEField, error) {
	if b.inject == nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding) Get(field *UEContextResumeRequestIEField) (*s18.ERABFailedToResumeListResumeReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeRequestRRCEstablishmentCauseIEBinding binds RRCEstablishmentCause to the UEContextResumeRequestIEs object set of TS 36.413.
type UEContextResumeRequestRRCEstablishmentCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RRCEstablishmentCauseValueCodec
	inject func(s00.RRCEstablishmentCause,

	) UEContextResumeRequestIEValue

	get func(*UEContextResumeRequestIEValue,

	) (*s00.RRCEstablishmentCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeRequestRRCEstablishmentCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeRequestRRCEstablishmentCauseIEBinding) Codec() s01.RRCEstablishmentCauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeRequestRRCEstablishmentCauseIEBinding) New(value s00.RRCEstablishmentCause,

) (UEContextResumeRequestIEField, error) {
	if b.inject == nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeRequestRRCEstablishmentCauseIEBinding) Get(field *UEContextResumeRequestIEField) (*s00.RRCEstablishmentCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeResponseMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextResumeResponseIEs object set of TS 36.413.
type UEContextResumeResponseMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextResumeResponseIEValue

	get func(*UEContextResumeResponseIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeResponseMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextResumeResponseIEField, error) {
	if b.inject == nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeResponseMMEUES1APIDIEBinding) Get(field *UEContextResumeResponseIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeResponseENBUES1APIDIEBinding binds ENBUES1APID to the UEContextResumeResponseIEs object set of TS 36.413.
type UEContextResumeResponseENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextResumeResponseIEValue

	get func(*UEContextResumeResponseIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeResponseENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextResumeResponseIEField, error) {
	if b.inject == nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeResponseENBUES1APIDIEBinding) Get(field *UEContextResumeResponseIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeResponseERABFailedToResumeListResumeResIEBinding binds ERABFailedToResumeListResumeRes to the UEContextResumeResponseIEs object set of TS 36.413.
type UEContextResumeResponseERABFailedToResumeListResumeResIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ERABFailedToResumeListResumeResValueCodec
	inject func(s18.ERABFailedToResumeListResumeRes,

	) UEContextResumeResponseIEValue

	get func(*UEContextResumeResponseIEValue,

	) (*s18.ERABFailedToResumeListResumeRes,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) Codec() s18.ERABFailedToResumeListResumeResValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) New(value s18.ERABFailedToResumeListResumeRes,

) (UEContextResumeResponseIEField, error) {
	if b.inject == nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeERABFailedToResumeListResumeResValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) Get(field *UEContextResumeResponseIEField) (*s18.ERABFailedToResumeListResumeRes,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeResponseCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the UEContextResumeResponseIEs object set of TS 36.413.
type UEContextResumeResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) UEContextResumeResponseIEValue

	get func(*UEContextResumeResponseIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeResponseCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (UEContextResumeResponseIEField, error) {
	if b.inject == nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeResponseCriticalityDiagnosticsIEBinding) Get(field *UEContextResumeResponseIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextResumeResponsePendingDataIndicationIEBinding binds PendingDataIndication to the UEContextResumeResponseIEs object set of TS 36.413.
type UEContextResumeResponsePendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) UEContextResumeResponseIEValue

	get func(*UEContextResumeResponseIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponsePendingDataIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponsePendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextResumeResponsePendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (UEContextResumeResponseIEField, error) {
	if b.inject == nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextResumeResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextResumeResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextResumeResponsePendingDataIndicationIEBinding) Get(field *UEContextResumeResponseIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEEarlyStatusTransferValueCodec is the concrete ValueCodec[MMEEarlyStatusTransfer].
type MMEEarlyStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransfer,

		error)
	encode func(MMEEarlyStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransfer, aper.DecodeState,

	) (MMEEarlyStatusTransfer, aper.Snapshot,

	)
	compare func(MMEEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferValueCodec) New(value MMEEarlyStatusTransfer,

) (MMEEarlyStatusTransferAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferValueCodec) EncodeAPER(value MMEEarlyStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c MMEEarlyStatusTransferValueCodec) encodeBudgetValue(value MMEEarlyStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferValueCodec) encodeChanged(value MMEEarlyStatusTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestValueCodec is the concrete ValueCodec[UEContextResumeRequest].
type UEContextResumeRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequest,

		error)
	encode func(UEContextResumeRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequest, aper.DecodeState,

	) (UEContextResumeRequest, aper.Snapshot,

	)
	compare func(UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestValueCodec) New(value UEContextResumeRequest,

) (UEContextResumeRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestValueCodec) EncodeAPER(value UEContextResumeRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestValueCodec) encodeBudgetValue(value UEContextResumeRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestValueCodec) encodeChanged(value UEContextResumeRequest,

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
func BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(fields UEContextResumeRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(fields s47.MMEEarlyStatusTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s47.BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s47.BridgeMMEEarlyStatusTransferIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s47.BridgeMMEEarlyStatusTransferIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// MMEEarlyStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueERABIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable) s47.MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s47.MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s47.MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec {
		sealed := s47.MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec{}
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "MMEEarlyStatusTransferIEValueERABIEContainerList"
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s47.MMEEarlyStatusTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s47.MMEEarlyStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s47.MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(&codec))(s47.MMEEarlyStatusTransferIEContainer(value), fresh, budget)
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeMMEEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEEarlyStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextResumeRequestIEs}} codec of TS 36.413.
func UEContextResumeRequestIEValueERABIEContainerListCodec(table s00.UEContextResumeRequestIEValueIETable) UEContextResumeRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextResumeRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextResumeRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextResumeRequestIEValueERABIEContainerListValueCodec{path: "UEContextResumeRequestIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextResumeRequestIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextResumeRequestIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextResumeRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextResumeRequestIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextResumeRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextResumeRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextResumeRequestIEValueERABIEContainerList, options aper.DecodeState) (UEContextResumeRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v UEContextResumeRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEContextResumeRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextResumeRequestIEs}} codec of TS 36.413.
func UEContextResumeRequestIEValueIEFieldTableCodec(table s00.UEContextResumeRequestIEValueIETable) UEContextResumeRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextResumeRequestIEValueIETableFieldBound(&table) {
		return UEContextResumeRequestIEFieldValueCodec{}
	}
	return UEContextResumeRequestIEFieldValueCodec{path: "UEContextResumeRequestIEField", decode: func(data []byte, options aper.DecodeState) (UEContextResumeRequestIEField, error) {
		var field UEContextResumeRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextResumeRequestIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextResumeRequestIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextResumeRequestIEField")
		}
		return field, nil
	}, encode: func(field UEContextResumeRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEContextResumeRequestIEField, options aper.DecodeState) (UEContextResumeRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextResumeRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEField(&v, &s)
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

// MMEEarlyStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueIETableCodec(table s00.MMEEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) s47.MMEEarlyStatusTransferIEContainerValueCodec {
	if !*s00.BridgeMMEEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return s47.MMEEarlyStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s47.MMEEarlyStatusTransferIEContainerValueCodec {
		sealed := s47.MMEEarlyStatusTransferIEContainerValueCodec{}
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldPath(&sealed) = "MMEEarlyStatusTransferIEContainer"
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s47.MMEEarlyStatusTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s47.MMEEarlyStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEContainer")
			}
			return fields, nil
		}
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s47.MMEEarlyStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s47.MMEEarlyStatusTransferIEContainer, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s47.MMEEarlyStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextResumeRequestIEs}} codec of TS 36.413.
func UEContextResumeRequestIEValueIETableCodec(table s00.UEContextResumeRequestIEValueIETable, bounds aper.ListBounds) UEContextResumeRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextResumeRequestIEValueIETableFieldBound(&table) {
		return UEContextResumeRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEContextResumeRequestIEContainerValueCodec{path: "UEContextResumeRequestIEContainer", decode: func(data []byte, options aper.DecodeState) (UEContextResumeRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextResumeRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextResumeRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextResumeRequestIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEContainer")
		}
		return fields, nil
	},
		encode: func(fields UEContextResumeRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEContextResumeRequestIEContainer, options aper.DecodeState) (UEContextResumeRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v UEContextResumeRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable) s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList"
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s47.MMEEarlyStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(&codec))(s47.MMEEarlyStatusTransferIEContainer(value), fresh, budget)
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextResumeRequestIEs}} codec of TS 36.413.
func UEContextResumeRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextResumeRequestIEValueIETable) UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextResumeRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec{path: "UEContextResumeRequestIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextResumeRequestIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextResumeRequestIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextResumeRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextResumeRequestIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextResumeRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextResumeRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextResumeRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEContextResumeRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextResumeRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCompareS1APProtocolErrorIEContainerList(
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

// MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEEarlyStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) s47.MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, bounds)
	if *s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s47.MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s47.MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s47.MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "MMEEarlyStatusTransferIEValueProtocolIEContainerList"
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s47.MMEEarlyStatusTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s47.BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(&codec))(s47.MMEEarlyStatusTransferIEContainer(value), fresh, budget)
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextResumeRequestIEValueProtocolIEContainerListCodec(table s00.UEContextResumeRequestIEValueIETable, bounds aper.ListBounds) UEContextResumeRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextResumeRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEContextResumeRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return UEContextResumeRequestIEValueProtocolIEContainerListValueCodec{path: "UEContextResumeRequestIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextResumeRequestIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextResumeRequestIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextResumeRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextResumeRequestIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextResumeRequestIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextResumeRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextResumeRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextResumeRequestIEValueProtocolIEContainerList, options aper.DecodeState) (UEContextResumeRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v UEContextResumeRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// mMEEarlyStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEEarlyStatusTransferIEValue].
type MMEEarlyStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s47.MMEEarlyStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s47.MMEEarlyStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uEContextResumeRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextResumeRequestIEValue].
type UEContextResumeRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEContextResumeRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEContextResumeRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEField(v *UEContextResumeRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEField(v *UEContextResumeRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// MMEEarlyStatusTransferAPERValue is the concrete APERValue[MMEEarlyStatusTransfer].
type MMEEarlyStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEEarlyStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferAPERValue) WithoutReplay() MMEEarlyStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestAPERValue is the concrete APERValue[UEContextResumeRequest].
type UEContextResumeRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextResumeRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestAPERValue) WithoutReplay() UEContextResumeRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// X2TNLConfigurationInfoExtIEsIEField uses the ProtocolIE-Field shape for object set X2TNLConfigurationInfo-ExtIEs of TS 36.413.
type X2TNLConfigurationInfoExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         X2TNLConfigurationInfoExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v X2TNLConfigurationInfoExtIEsIEField) WithoutReplay() X2TNLConfigurationInfoExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *X2TNLConfigurationInfoExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *X2TNLConfigurationInfoExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *X2TNLConfigurationInfoExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2TNLConfigurationInfoExtIEsIEField{}
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
	var zero X2TNLConfigurationInfoExtIEsValue

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

// X2TNLConfigurationInfoExtIEsIEContainer uses the ProtocolIE-Container shape for object set X2TNLConfigurationInfo-ExtIEs of TS 36.413: a list of X2TNLConfigurationInfoExtIEsIEField values.
type X2TNLConfigurationInfoExtIEsIEContainer []X2TNLConfigurationInfoExtIEsIEField

func BridgeMMEEarlyStatusTransferIEValueCompareS1APERABIEContainerList(v *s47.MMEEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeRequestIEValueERABIEContainerList].
type UEContextResumeRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequestIEValueERABIEContainerList, error)
	encode  func(UEContextResumeRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextResumeRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextResumeRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestIEValueERABIEContainerListValueCodec) New(value UEContextResumeRequestIEValueERABIEContainerList) (UEContextResumeRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextResumeRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextResumeRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextResumeRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextResumeRequestIEValueERABIEContainerList []UEContextResumeRequestIEValueProtocolIESingleContainer

func BridgeUEContextResumeRequestIEValueCaptureS1APERABIEContainerList(v *UEContextResumeRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeRequestIEValueCompareS1APERABIEContainerList(v *UEContextResumeRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeResponseIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeResponseIEValueERABIEContainerList].
type UEContextResumeResponseIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueERABIEContainerList, error)
	encode  func(UEContextResumeResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextResumeResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeResponseIEValueERABIEContainerListValueCodec) New(value UEContextResumeResponseIEValueERABIEContainerList) (UEContextResumeResponseIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeResponseIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeResponseIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeResponseIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeResponseIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeResponseIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeResponseIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextResumeResponseIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeResponseIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeResponseIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextResumeResponseIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeResponseIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextResumeResponseIEs}} of TS 36.413: a list of information element fields.
type UEContextResumeResponseIEValueERABIEContainerList []UEContextResumeResponseIEValueProtocolIESingleContainer

// X2TNLConfigurationInfoExtIEsExtFieldValueCodec is the concrete ValueCodec[X2TNLConfigurationInfoExtIEsExtField].
type X2TNLConfigurationInfoExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtField, error)
	encode  func(X2TNLConfigurationInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(X2TNLConfigurationInfoExtIEsExtField, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot)
	compare func(X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c X2TNLConfigurationInfoExtIEsExtFieldValueCodec) New(value X2TNLConfigurationInfoExtIEsExtField) (X2TNLConfigurationInfoExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c X2TNLConfigurationInfoExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (X2TNLConfigurationInfoExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return X2TNLConfigurationInfoExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c X2TNLConfigurationInfoExtIEsExtFieldValueCodec) EncodeAPER(value X2TNLConfigurationInfoExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c X2TNLConfigurationInfoExtIEsExtFieldValueCodec) encodeBudgetValue(value X2TNLConfigurationInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c X2TNLConfigurationInfoExtIEsExtFieldValueCodec) encodeChanged(value X2TNLConfigurationInfoExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// X2TNLConfigurationInfoExtIEsExtContainerValueCodec is the concrete ValueCodec[X2TNLConfigurationInfoExtIEsExtContainer].
type X2TNLConfigurationInfoExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtContainer, error)
	encode  func(X2TNLConfigurationInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(X2TNLConfigurationInfoExtIEsExtContainer, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot)
	compare func(X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c X2TNLConfigurationInfoExtIEsExtContainerValueCodec) New(value X2TNLConfigurationInfoExtIEsExtContainer) (X2TNLConfigurationInfoExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c X2TNLConfigurationInfoExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (X2TNLConfigurationInfoExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return X2TNLConfigurationInfoExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c X2TNLConfigurationInfoExtIEsExtContainerValueCodec) EncodeAPER(value X2TNLConfigurationInfoExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c X2TNLConfigurationInfoExtIEsExtContainerValueCodec) encodeBudgetValue(value X2TNLConfigurationInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c X2TNLConfigurationInfoExtIEsExtContainerValueCodec) encodeChanged(value X2TNLConfigurationInfoExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestIEFieldValueCodec is the concrete ValueCodec[UEContextResumeRequestIEField].
type UEContextResumeRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequestIEField, error)
	encode  func(UEContextResumeRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequestIEField, aper.DecodeState) (UEContextResumeRequestIEField, aper.Snapshot)
	compare func(UEContextResumeRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestIEFieldValueCodec) New(value UEContextResumeRequestIEField) (UEContextResumeRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestIEFieldValueCodec) EncodeAPER(value UEContextResumeRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestIEFieldValueCodec) encodeBudgetValue(value UEContextResumeRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestIEFieldValueCodec) encodeChanged(value UEContextResumeRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeResponseIEFieldValueCodec is the concrete ValueCodec[UEContextResumeResponseIEField].
type UEContextResumeResponseIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeResponseIEField, error)
	encode  func(UEContextResumeResponseIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeResponseIEField, aper.DecodeState) (UEContextResumeResponseIEField, aper.Snapshot)
	compare func(UEContextResumeResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeResponseIEFieldValueCodec) New(value UEContextResumeResponseIEField) (UEContextResumeResponseIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeResponseIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeResponseIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeResponseIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeResponseIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeResponseIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeResponseIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeResponseIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeResponseIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeResponseIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeResponseIEFieldValueCodec) EncodeAPER(value UEContextResumeResponseIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeResponseIEFieldValueCodec) encodeBudgetValue(value UEContextResumeResponseIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeResponseIEFieldValueCodec) encodeChanged(value UEContextResumeResponseIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestIEContainerValueCodec is the concrete ValueCodec[UEContextResumeRequestIEContainer].
type UEContextResumeRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequestIEContainer, error)
	encode  func(UEContextResumeRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequestIEContainer, aper.DecodeState) (UEContextResumeRequestIEContainer, aper.Snapshot)
	compare func(UEContextResumeRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestIEContainerValueCodec) New(value UEContextResumeRequestIEContainer) (UEContextResumeRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestIEContainerValueCodec) EncodeAPER(value UEContextResumeRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestIEContainerValueCodec) encodeBudgetValue(value UEContextResumeRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestIEContainerValueCodec) encodeChanged(value UEContextResumeRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeResponseIEContainerValueCodec is the concrete ValueCodec[UEContextResumeResponseIEContainer].
type UEContextResumeResponseIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeResponseIEContainer, error)
	encode  func(UEContextResumeResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeResponseIEContainer, aper.DecodeState) (UEContextResumeResponseIEContainer, aper.Snapshot)
	compare func(UEContextResumeResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeResponseIEContainerValueCodec) New(value UEContextResumeResponseIEContainer) (UEContextResumeResponseIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeResponseIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeResponseIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeResponseIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeResponseIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeResponseIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeResponseIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeResponseIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeResponseIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeResponseIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeResponseIEContainerValueCodec) EncodeAPER(value UEContextResumeResponseIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeResponseIEContainerValueCodec) encodeBudgetValue(value UEContextResumeResponseIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeResponseIEContainerValueCodec) encodeChanged(value UEContextResumeResponseIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s47.MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeRequestIEValueProtocolErrorIEContainerList].
type UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextResumeRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextResumeRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextResumeRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextResumeRequestIEValueProtocolErrorIEContainerList) (UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextResumeRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextResumeRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextResumeRequestIEValueProtocolErrorIEContainerList []UEContextResumeRequestIEValueProtocolIESingleContainer

func BridgeUEContextResumeRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *UEContextResumeRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeRequestIEValueCompareS1APProtocolErrorIEContainerList(v *UEContextResumeRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeResponseIEValueProtocolErrorIEContainerList].
type UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextResumeResponseIEValueProtocolErrorIEContainerList) (UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextResumeResponseIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeResponseIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextResumeResponseIEs}} of TS 36.413: a list of information element fields.
type UEContextResumeResponseIEValueProtocolErrorIEContainerList []UEContextResumeResponseIEValueProtocolIESingleContainer

func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(v *s47.MMEEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeRequestIEValueProtocolIEContainerList].
type UEContextResumeRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeRequestIEValueProtocolIEContainerList, error)
	encode  func(UEContextResumeRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextResumeRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextResumeRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeRequestIEValueProtocolIEContainerListValueCodec) New(value UEContextResumeRequestIEValueProtocolIEContainerList) (UEContextResumeRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextResumeRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextResumeRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextResumeRequestIEValueProtocolIEContainerList []UEContextResumeRequestIEValueProtocolIESingleContainer

func BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEContainerList(v *UEContextResumeRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEContainerList(v *UEContextResumeRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeResponseIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextResumeResponseIEValueProtocolIEContainerList].
type UEContextResumeResponseIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueProtocolIEContainerList, error)
	encode  func(UEContextResumeResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextResumeResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) New(value UEContextResumeResponseIEValueProtocolIEContainerList) (UEContextResumeResponseIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeResponseIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeResponseIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextResumeResponseIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextResumeResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextResumeResponseIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeResponseIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeResponseIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextResumeResponseIEValueProtocolIEContainerList []UEContextResumeResponseIEValueProtocolIESingleContainer

func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *s47.MMEEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s47.BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextResumeRequestIEValueERABIEContainerList].
type UEContextResumeRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextResumeRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextResumeRequestIEs}} of TS 36.413: a single information element field.
type UEContextResumeRequestIEValueProtocolIESingleContainer = UEContextResumeRequestIEField

func BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIESingleContainer(v *UEContextResumeRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextResumeRequestIEValueCompareS1APProtocolIESingleContainer(v *UEContextResumeRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEContextResumeResponseIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextResumeResponseIEValueERABIEContainerList].
type UEContextResumeResponseIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeResponseIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeResponseIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextResumeResponseIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeResponseIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextResumeResponseIEs}} of TS 36.413: a single information element field.
type UEContextResumeResponseIEValueProtocolIESingleContainer = UEContextResumeResponseIEField

// X2TNLConfigurationInfoExtIEsExtFieldAPERValue is the concrete APERValue[X2TNLConfigurationInfoExtIEsExtField].
type X2TNLConfigurationInfoExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         X2TNLConfigurationInfoExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v X2TNLConfigurationInfoExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v X2TNLConfigurationInfoExtIEsExtFieldAPERValue) WithoutReplay() X2TNLConfigurationInfoExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// X2TNLConfigurationInfoExtIEsExtContainerAPERValue is the concrete APERValue[X2TNLConfigurationInfoExtIEsExtContainer].
type X2TNLConfigurationInfoExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         X2TNLConfigurationInfoExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v X2TNLConfigurationInfoExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v X2TNLConfigurationInfoExtIEsExtContainerAPERValue) WithoutReplay() X2TNLConfigurationInfoExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestIEFieldAPERValue is the concrete APERValue[UEContextResumeRequestIEField].
type UEContextResumeRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEFieldAPERValue) WithoutReplay() UEContextResumeRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeResponseIEFieldAPERValue is the concrete APERValue[UEContextResumeResponseIEField].
type UEContextResumeResponseIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeResponseIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeResponseIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEFieldAPERValue) WithoutReplay() UEContextResumeResponseIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestIEContainerAPERValue is the concrete APERValue[UEContextResumeRequestIEContainer].
type UEContextResumeRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEContainerAPERValue) WithoutReplay() UEContextResumeRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeResponseIEContainerAPERValue is the concrete APERValue[UEContextResumeResponseIEContainer].
type UEContextResumeResponseIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeResponseIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeResponseIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEContainerAPERValue) WithoutReplay() UEContextResumeResponseIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextResumeRequestIEValueProtocolErrorIEContainerList].
type UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextResumeRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextResumeResponseIEValueProtocolErrorIEContainerList].
type UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeResponseIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextResumeResponseIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextResumeRequestIEValueProtocolIEContainerList].
type UEContextResumeRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextResumeRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeResponseIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextResumeResponseIEValueProtocolIEContainerList].
type UEContextResumeResponseIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextResumeResponseIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeResponseIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeResponseIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextResumeResponseIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferListComplete(v *BearersSubjectToEarlyStatusTransferListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v *BearersSubjectToEarlyStatusTransferListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferListComplete(v *BearersSubjectToStatusTransferListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APBearersSubjectToStatusTransferList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v *BearersSubjectToStatusTransferListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APBearersSubjectToStatusTransferList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBluetoothMeasConfigNameListComplete(v *BluetoothMeasConfigNameListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBluetoothMeasConfigNameListComplete(v *BluetoothMeasConfigNameListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCNTypeRestrictionsComplete(v *CNTypeRestrictionsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCNTypeRestrictions(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCNTypeRestrictionsComplete(v *CNTypeRestrictionsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCNTypeRestrictions(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCSGIdListComplete(v *CSGIdListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCSGIdList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGIdListComplete(v *CSGIdListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCSGIdList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinEAIComplete(v *CancelledCellinEAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCancelledCellinEAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinEAIComplete(v *CancelledCellinEAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCancelledCellinEAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinTAIComplete(v *CancelledCellinTAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCancelledCellinTAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinTAIComplete(v *CancelledCellinTAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCancelledCellinTAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidateCellListComplete(v *CandidateCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCandidateCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidateCellListComplete(v *CandidateCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCandidateCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidatePCIListComplete(v *CandidatePCIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCandidatePCIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidatePCIListComplete(v *CandidatePCIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCandidatePCIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDBroadcastComplete(v *CellIDBroadcastComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellIDBroadcast(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDBroadcastComplete(v *CellIDBroadcastComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCellIDBroadcast(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDCancelledComplete(v *CellIDCancelledComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellIDCancelled(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDCancelledComplete(v *CellIDCancelledComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCellIDCancelled(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIdListforMDTComplete(v *CellIdListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellIdListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIdListforMDTComplete(v *CellIdListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCellIdListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIdListforQMCComplete(v *CellIdListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellIdListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIdListforQMCComplete(v *CellIdListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APCellIdListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellsToActivateListComplete(v *CellsToActivateListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCellsToActivateList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellsToActivateListComplete(v *CellsToActivateListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APCellsToActivateList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCompletedCellinEAIComplete(v *CompletedCellinEAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCompletedCellinEAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCompletedCellinEAIComplete(v *CompletedCellinEAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APCompletedCellinEAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCompletedCellinTAIComplete(v *CompletedCellinTAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCompletedCellinTAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCompletedCellinTAIComplete(v *CompletedCellinTAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APCompletedCellinTAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APConnectedengNBListComplete(v *ConnectedengNBListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCaptureS1APConnectedengNBList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APConnectedengNBListComplete(v *ConnectedengNBListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCompareS1APConnectedengNBList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDAPSResponseInfoListComplete(v *DAPSResponseInfoListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCaptureS1APDAPSResponseInfoList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDAPSResponseInfoListComplete(v *DAPSResponseInfoListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APDAPSResponseInfoList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APECGIListComplete(v *ECGIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APECGIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APECGIListComplete(v *ECGIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APECGIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APECGIListForRestartComplete(v *ECGIListForRestartComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APECGIListForRestart(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APECGIListForRestartComplete(v *ECGIListForRestartComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APECGIListForRestart(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBIndirectX2TransportLayerAddressesComplete(v *ENBIndirectX2TransportLayerAddressesComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APENBIndirectX2TransportLayerAddresses(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBIndirectX2TransportLayerAddressesComplete(v *ENBIndirectX2TransportLayerAddressesComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APENBIndirectX2TransportLayerAddresses(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBX2ExtTLAsComplete(v *ENBX2ExtTLAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APENBX2ExtTLAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2ExtTLAsComplete(v *ENBX2ExtTLAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APENBX2ExtTLAs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBX2GTPTLAsComplete(v *ENBX2GTPTLAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APENBX2GTPTLAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2GTPTLAsComplete(v *ENBX2GTPTLAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APENBX2GTPTLAs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBX2TLAsComplete(v *ENBX2TLAsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APENBX2TLAs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBX2TLAsComplete(v *ENBX2TLAsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APENBX2TLAs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APEPLMNsComplete(v *EPLMNsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEPLMNs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APEPLMNsComplete(v *EPLMNsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APEPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABAdmittedListComplete(v *ERABAdmittedListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCaptureS1APERABAdmittedList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABAdmittedListComplete(v *ERABAdmittedListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APERABAdmittedList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABFailedToResumeListResumeReqComplete(v *ERABFailedToResumeListResumeReqComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCaptureS1APERABFailedToResumeListResumeReq(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedToResumeListResumeReqComplete(v *ERABFailedToResumeListResumeReqComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCompareS1APERABFailedToResumeListResumeReq(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APERABFailedToResumeListResumeResComplete(v *ERABFailedToResumeListResumeResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCaptureS1APERABFailedToResumeListResumeRes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APERABFailedToResumeListResumeResComplete(v *ERABFailedToResumeListResumeResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s29.BridgeCompareS1APERABFailedToResumeListResumeRes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEEarlyStatusTransfer(v *MMEEarlyStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s47.BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEEarlyStatusTransfer(v *MMEEarlyStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s47.BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextResumeRequest(v *UEContextResumeRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextResumeRequest(v *UEContextResumeRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextResumeRequestIEValue(v *UEContextResumeRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(235):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeListResumeReq == nil)
				if v.rowERABFailedToResumeListResumeReq != nil {
					s29.BridgeCaptureS1APERABFailedToResumeListResumeReq(v.rowERABFailedToResumeListResumeReq, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s00.BridgeCaptureS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeRequestIEValue) captureSemantics(s aper.SemanticCapture) UEContextResumeRequestIEValue {
	BridgeCaptureS1APUEContextResumeRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextResumeRequestIEValue(v *UEContextResumeRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(235):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeListResumeReq == nil)
				if v.rowERABFailedToResumeListResumeReq != nil {
					s29.BridgeCompareS1APERABFailedToResumeListResumeReq(v.rowERABFailedToResumeListResumeReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(245):
			{
				f := s.Begin()
				s.Bool(v.rowRRCResumeCause == nil)
				if v.rowRRCResumeCause != nil {
					s08.BridgeCompareS1APRRCEstablishmentCause(v.rowRRCResumeCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextResumeRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextResumeResponseIEValue(v *UEContextResumeResponseIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(237):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeListResumeRes == nil)
				if v.rowERABFailedToResumeListResumeRes != nil {
					s29.BridgeCaptureS1APERABFailedToResumeListResumeRes(v.rowERABFailedToResumeListResumeRes, s)
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
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s36.BridgeCaptureS1APSecurityContext(v.rowSecurityContext, s)
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
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeResponseIEValue) captureSemantics(s aper.SemanticCapture) UEContextResumeResponseIEValue {
	BridgeCaptureS1APUEContextResumeResponseIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextResumeResponseIEValue(v *UEContextResumeResponseIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(237):
			{
				f := s.Begin()
				s.Bool(v.rowERABFailedToResumeListResumeRes == nil)
				if v.rowERABFailedToResumeListResumeRes != nil {
					s29.BridgeCompareS1APERABFailedToResumeListResumeRes(v.rowERABFailedToResumeListResumeRes, s)
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
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s36.BridgeCompareS1APSecurityContext(v.rowSecurityContext, s)
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
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextResumeResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextResumeResponseIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APX2TNLConfigurationInfoExtIEsValue(v *X2TNLConfigurationInfoExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(153):
			{
				f := s.Begin()
				s.Bool(v.rowENBX2ExtendedTransportLayerAddresses == nil)
				if v.rowENBX2ExtendedTransportLayerAddresses != nil {
					s25.BridgeCaptureS1APENBX2ExtTLAs(v.rowENBX2ExtendedTransportLayerAddresses, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(193):
			{
				f := s.Begin()
				s.Bool(v.rowENBIndirectX2TransportLayerAddresses == nil)
				if v.rowENBIndirectX2TransportLayerAddresses != nil {
					s00.BridgeCaptureS1APENBIndirectX2TransportLayerAddresses(v.rowENBIndirectX2TransportLayerAddresses, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v X2TNLConfigurationInfoExtIEsValue) captureSemantics(s aper.SemanticCapture) X2TNLConfigurationInfoExtIEsValue {
	BridgeCaptureS1APX2TNLConfigurationInfoExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APX2TNLConfigurationInfoExtIEsValue(v *X2TNLConfigurationInfoExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(153):
			{
				f := s.Begin()
				s.Bool(v.rowENBX2ExtendedTransportLayerAddresses == nil)
				if v.rowENBX2ExtendedTransportLayerAddresses != nil {
					s28.BridgeCompareS1APENBX2ExtTLAs(v.rowENBX2ExtendedTransportLayerAddresses, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(193):
			{
				f := s.Begin()
				s.Bool(v.rowENBIndirectX2TransportLayerAddresses == nil)
				if v.rowENBIndirectX2TransportLayerAddresses != nil {
					s08.BridgeCompareS1APENBIndirectX2TransportLayerAddresses(v.rowENBIndirectX2TransportLayerAddresses, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v X2TNLConfigurationInfoExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APX2TNLConfigurationInfoExtIEsValue(&v, &s)
	return s
}

// BearersSubjectToStatusTransferListComplete carries a complete BearersSubjectToStatusTransferList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToStatusTransferListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s25.BearersSubjectToStatusTransferList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToStatusTransferListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERBearersSubjectToStatusTransferListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToStatusTransferList from APER format.
func (v *BearersSubjectToStatusTransferListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BearersSubjectToStatusTransferListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	bb.EnterComponent("BearersSubjectToStatusTransferList")
	value, err := BridgeUnmarshalAPERBearersSubjectToStatusTransferListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBearersSubjectToStatusTransferList encodes a BearersSubjectToStatusTransferList list to APER.
func BridgeMarshalAPERBearersSubjectToStatusTransferList(list BearersSubjectToStatusTransferListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBearersSubjectToStatusTransferList decodes a BearersSubjectToStatusTransferList list from APER.
func BridgeUnmarshalAPERBearersSubjectToStatusTransferList(data []byte) (BearersSubjectToStatusTransferListComplete, error) {
	var value BearersSubjectToStatusTransferListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBearersSubjectToStatusTransferListFrom decodes a BearersSubjectToStatusTransferList list from bb.
func BridgeUnmarshalAPERBearersSubjectToStatusTransferListFrom(bb *aper.BitBuffer) (s25.BearersSubjectToStatusTransferList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToStatusTransferListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToStatusTransferListInto(v *s25.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s25.BearersSubjectToStatusTransferList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s25.BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s25.BridgeBearersSubjectToStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// BearersSubjectToEarlyStatusTransferListComplete carries a complete BearersSubjectToEarlyStatusTransferList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToEarlyStatusTransferListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.BearersSubjectToEarlyStatusTransferList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToEarlyStatusTransferList from APER format.
func (v *BearersSubjectToEarlyStatusTransferListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	bb.EnterComponent("BearersSubjectToEarlyStatusTransferList")
	value, err := BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBearersSubjectToEarlyStatusTransferList encodes a BearersSubjectToEarlyStatusTransferList list to APER.
func BridgeMarshalAPERBearersSubjectToEarlyStatusTransferList(list BearersSubjectToEarlyStatusTransferListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferList decodes a BearersSubjectToEarlyStatusTransferList list from APER.
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferList(data []byte) (BearersSubjectToEarlyStatusTransferListComplete, error) {
	var value BearersSubjectToEarlyStatusTransferListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom decodes a BearersSubjectToEarlyStatusTransferList list from bb.
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom(bb *aper.BitBuffer) (s17.BearersSubjectToEarlyStatusTransferList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListInto(v *s25.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.BearersSubjectToEarlyStatusTransferList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPERBearersSubjectToDLDiscardingList encodes a BearersSubjectToDLDiscardingList list to APER.
func BridgeMarshalAPERBearersSubjectToDLDiscardingList(list s47.BearersSubjectToDLDiscardingListComplete) ([]byte, error) {
	return s47.BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERBearersSubjectToDLDiscardingList decodes a BearersSubjectToDLDiscardingList list from APER.
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingList(data []byte) (s47.BearersSubjectToDLDiscardingListComplete, error) {
	var value s47.BearersSubjectToDLDiscardingListComplete
	if err := s47.BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// BluetoothMeasConfigNameListComplete carries a complete BluetoothMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BluetoothMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.BluetoothMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BluetoothMeasConfigNameListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERBluetoothMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BluetoothMeasConfigNameList from APER format.
func (v *BluetoothMeasConfigNameListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *BluetoothMeasConfigNameListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	bb.EnterComponent("BluetoothMeasConfigNameList")
	value, err := BridgeUnmarshalAPERBluetoothMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BluetoothMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBluetoothMeasConfigNameList encodes a BluetoothMeasConfigNameList list to APER.
func BridgeMarshalAPERBluetoothMeasConfigNameList(list BluetoothMeasConfigNameListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBluetoothMeasConfigNameList decodes a BluetoothMeasConfigNameList list from APER.
func BridgeUnmarshalAPERBluetoothMeasConfigNameList(data []byte) (BluetoothMeasConfigNameListComplete, error) {
	var value BluetoothMeasConfigNameListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBluetoothMeasConfigNameListFrom decodes a BluetoothMeasConfigNameList list from bb.
func BridgeUnmarshalAPERBluetoothMeasConfigNameListFrom(bb *aper.BitBuffer) (s00.BluetoothMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERBluetoothMeasConfigNameListListValue
	if err := BridgeUnmarshalAPERBluetoothMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBluetoothMeasConfigNameListInto(v *s00.BridgeAsn1cAPERBluetoothMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.BluetoothMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 248, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CancelledCellinEAIComplete carries a complete CancelledCellinEAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CancelledCellinEAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CancelledCellinEAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CancelledCellinEAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCancelledCellinEAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CancelledCellinEAI from APER format.
func (v *CancelledCellinEAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CancelledCellinEAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	bb.EnterComponent("CancelledCellinEAI")
	value, err := BridgeUnmarshalAPERCancelledCellinEAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinEAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCancelledCellinEAI encodes a CancelledCellinEAI list to APER.
func BridgeMarshalAPERCancelledCellinEAI(list CancelledCellinEAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCancelledCellinEAI decodes a CancelledCellinEAI list from APER.
func BridgeUnmarshalAPERCancelledCellinEAI(data []byte) (CancelledCellinEAIComplete, error) {
	var value CancelledCellinEAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCancelledCellinEAIFrom decodes a CancelledCellinEAI list from bb.
func BridgeUnmarshalAPERCancelledCellinEAIFrom(bb *aper.BitBuffer) (s20.CancelledCellinEAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCancelledCellinEAIListValue
	if err := BridgeUnmarshalAPERCancelledCellinEAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCancelledCellinEAIInto(v *s25.BridgeAsn1cAPERCancelledCellinEAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CancelledCellinEAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CancelledCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCancelledCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CancelledCellinTAIComplete carries a complete CancelledCellinTAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CancelledCellinTAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CancelledCellinTAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CancelledCellinTAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCancelledCellinTAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CancelledCellinTAI from APER format.
func (v *CancelledCellinTAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CancelledCellinTAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	bb.EnterComponent("CancelledCellinTAI")
	value, err := BridgeUnmarshalAPERCancelledCellinTAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinTAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCancelledCellinTAI encodes a CancelledCellinTAI list to APER.
func BridgeMarshalAPERCancelledCellinTAI(list CancelledCellinTAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCancelledCellinTAI decodes a CancelledCellinTAI list from APER.
func BridgeUnmarshalAPERCancelledCellinTAI(data []byte) (CancelledCellinTAIComplete, error) {
	var value CancelledCellinTAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCancelledCellinTAIFrom decodes a CancelledCellinTAI list from bb.
func BridgeUnmarshalAPERCancelledCellinTAIFrom(bb *aper.BitBuffer) (s20.CancelledCellinTAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCancelledCellinTAIListValue
	if err := BridgeUnmarshalAPERCancelledCellinTAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCancelledCellinTAIInto(v *s25.BridgeAsn1cAPERCancelledCellinTAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CancelledCellinTAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CancelledCellinTAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCancelledCellinTAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIDBroadcastComplete carries a complete CellIDBroadcast encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIDBroadcastComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CellIDBroadcast
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIDBroadcastComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCellIDBroadcastTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIDBroadcast from APER format.
func (v *CellIDBroadcastComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIDBroadcastComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	bb.EnterComponent("CellIDBroadcast")
	value, err := BridgeUnmarshalAPERCellIDBroadcastFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDBroadcast")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIDBroadcast encodes a CellIDBroadcast list to APER.
func BridgeMarshalAPERCellIDBroadcast(list CellIDBroadcastComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIDBroadcast decodes a CellIDBroadcast list from APER.
func BridgeUnmarshalAPERCellIDBroadcast(data []byte) (CellIDBroadcastComplete, error) {
	var value CellIDBroadcastComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIDBroadcastFrom decodes a CellIDBroadcast list from bb.
func BridgeUnmarshalAPERCellIDBroadcastFrom(bb *aper.BitBuffer) (s20.CellIDBroadcast, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCellIDBroadcastListValue
	if err := BridgeUnmarshalAPERCellIDBroadcastInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIDBroadcastInto(v *s25.BridgeAsn1cAPERCellIDBroadcastListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CellIDBroadcast, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CellIDBroadcastItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCellIDBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIDCancelledComplete carries a complete CellIDCancelled encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIDCancelledComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CellIDCancelled
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIDCancelledComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCellIDCancelledTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIDCancelled from APER format.
func (v *CellIDCancelledComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIDCancelledComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	bb.EnterComponent("CellIDCancelled")
	value, err := BridgeUnmarshalAPERCellIDCancelledFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDCancelled")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIDCancelled encodes a CellIDCancelled list to APER.
func BridgeMarshalAPERCellIDCancelled(list CellIDCancelledComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIDCancelled decodes a CellIDCancelled list from APER.
func BridgeUnmarshalAPERCellIDCancelled(data []byte) (CellIDCancelledComplete, error) {
	var value CellIDCancelledComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIDCancelledFrom decodes a CellIDCancelled list from bb.
func BridgeUnmarshalAPERCellIDCancelledFrom(bb *aper.BitBuffer) (s20.CellIDCancelled, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCellIDCancelledListValue
	if err := BridgeUnmarshalAPERCellIDCancelledInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIDCancelledInto(v *s25.BridgeAsn1cAPERCellIDCancelledListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CellIDCancelled, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CellIDCancelledItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCellIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIdListforMDTComplete carries a complete CellIdListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIdListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CellIdListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIdListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCellIdListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIdListforMDT from APER format.
func (v *CellIdListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIdListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	bb.EnterComponent("CellIdListforMDT")
	value, err := BridgeUnmarshalAPERCellIdListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIdListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIdListforMDT encodes a CellIdListforMDT list to APER.
func BridgeMarshalAPERCellIdListforMDT(list CellIdListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIdListforMDT decodes a CellIdListforMDT list from APER.
func BridgeUnmarshalAPERCellIdListforMDT(data []byte) (CellIdListforMDTComplete, error) {
	var value CellIdListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIdListforMDTFrom decodes a CellIdListforMDT list from bb.
func BridgeUnmarshalAPERCellIdListforMDTFrom(bb *aper.BitBuffer) (s20.CellIdListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCellIdListforMDTListValue
	if err := BridgeUnmarshalAPERCellIdListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIdListforMDTInto(v *s25.BridgeAsn1cAPERCellIdListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CellIdListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIdListforQMCComplete carries a complete CellIdListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIdListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CellIdListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIdListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCellIdListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIdListforQMC from APER format.
func (v *CellIdListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellIdListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	bb.EnterComponent("CellIdListforQMC")
	value, err := BridgeUnmarshalAPERCellIdListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIdListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIdListforQMC encodes a CellIdListforQMC list to APER.
func BridgeMarshalAPERCellIdListforQMC(list CellIdListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIdListforQMC decodes a CellIdListforQMC list from APER.
func BridgeUnmarshalAPERCellIdListforQMC(data []byte) (CellIdListforQMCComplete, error) {
	var value CellIdListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIdListforQMCFrom decodes a CellIdListforQMC list from bb.
func BridgeUnmarshalAPERCellIdListforQMCFrom(bb *aper.BitBuffer) (s20.CellIdListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCellIdListforQMCListValue
	if err := BridgeUnmarshalAPERCellIdListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIdListforQMCInto(v *s25.BridgeAsn1cAPERCellIdListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CellIdListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CNTypeRestrictionsComplete carries a complete CNTypeRestrictions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CNTypeRestrictionsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s16.CNTypeRestrictions
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CNTypeRestrictionsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCNTypeRestrictionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CNTypeRestrictions from APER format.
func (v *CNTypeRestrictionsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CNTypeRestrictionsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	bb.EnterComponent("CNTypeRestrictions")
	value, err := BridgeUnmarshalAPERCNTypeRestrictionsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	padding, err := aper.CaptureFinalBits(bb, "CNTypeRestrictions")
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCNTypeRestrictions encodes a CNTypeRestrictions list to APER.
func BridgeMarshalAPERCNTypeRestrictions(list CNTypeRestrictionsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCNTypeRestrictions decodes a CNTypeRestrictions list from APER.
func BridgeUnmarshalAPERCNTypeRestrictions(data []byte) (CNTypeRestrictionsComplete, error) {
	var value CNTypeRestrictionsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCNTypeRestrictionsFrom decodes a CNTypeRestrictions list from bb.
func BridgeUnmarshalAPERCNTypeRestrictionsFrom(bb *aper.BitBuffer) (s16.CNTypeRestrictions, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCNTypeRestrictionsListValue
	if err := BridgeUnmarshalAPERCNTypeRestrictionsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCNTypeRestrictionsInto(v *s25.BridgeAsn1cAPERCNTypeRestrictionsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.CNTypeRestrictions, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.CNTypeRestrictionsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeCNTypeRestrictionsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ConnectedengNBListComplete carries a complete ConnectedengNBList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ConnectedengNBListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s40.ConnectedengNBList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ConnectedengNBListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s40.BridgeMarshalAPERConnectedengNBListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ConnectedengNBList from APER format.
func (v *ConnectedengNBListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ConnectedengNBListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBList")
	}
	bb.EnterComponent("ConnectedengNBList")
	value, err := BridgeUnmarshalAPERConnectedengNBListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ConnectedengNBList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ConnectedengNBList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERConnectedengNBList encodes a ConnectedengNBList list to APER.
func BridgeMarshalAPERConnectedengNBList(list ConnectedengNBListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERConnectedengNBList decodes a ConnectedengNBList list from APER.
func BridgeUnmarshalAPERConnectedengNBList(data []byte) (ConnectedengNBListComplete, error) {
	var value ConnectedengNBListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERConnectedengNBListFrom decodes a ConnectedengNBList list from bb.
func BridgeUnmarshalAPERConnectedengNBListFrom(bb *aper.BitBuffer) (s40.ConnectedengNBList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s40.BridgeAsn1cAPERConnectedengNBListListValue
	if err := BridgeUnmarshalAPERConnectedengNBListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERConnectedengNBListInto(v *s40.BridgeAsn1cAPERConnectedengNBListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s40.ConnectedengNBList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s40.ConnectedengNBItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s40.BridgeConnectedengNBItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CSGIdListComplete carries a complete CSGIdList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CSGIdListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CSGIdList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CSGIdListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCSGIdListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CSGIdList from APER format.
func (v *CSGIdListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CSGIdListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	bb.EnterComponent("CSGIdList")
	value, err := BridgeUnmarshalAPERCSGIdListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGIdList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCSGIdList encodes a CSGIdList list to APER.
func BridgeMarshalAPERCSGIdList(list CSGIdListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCSGIdList decodes a CSGIdList list from APER.
func BridgeUnmarshalAPERCSGIdList(data []byte) (CSGIdListComplete, error) {
	var value CSGIdListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCSGIdListFrom decodes a CSGIdList list from bb.
func BridgeUnmarshalAPERCSGIdListFrom(bb *aper.BitBuffer) (s17.CSGIdList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCSGIdListListValue
	if err := BridgeUnmarshalAPERCSGIdListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCSGIdListInto(v *s25.BridgeAsn1cAPERCSGIdListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CSGIdList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CSGIdListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCSGIdListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CriticalityDiagnosticsIEList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CriticalityDiagnosticsIEListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CriticalityDiagnosticsIEList from APER format.
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	bb.EnterComponent("CriticalityDiagnosticsIEList")
	value, err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a CriticalityDiagnosticsIEList list to APER.
func BridgeMarshalAPERCriticalityDiagnosticsIEList(list CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a CriticalityDiagnosticsIEList list from APER.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEList(data []byte) (CriticalityDiagnosticsIEListComplete, error) {
	var value CriticalityDiagnosticsIEListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCriticalityDiagnosticsIEListFrom decodes a CriticalityDiagnosticsIEList list from bb.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb *aper.BitBuffer) (s17.CriticalityDiagnosticsIEList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue
	if err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(v *s25.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CriticalityDiagnosticsIEList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CriticalityDiagnosticsIEItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCriticalityDiagnosticsIEItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// DAPSResponseInfoListComplete carries a complete DAPSResponseInfoList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type DAPSResponseInfoListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.DAPSResponseInfoList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *DAPSResponseInfoListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERDAPSResponseInfoListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes DAPSResponseInfoList from APER format.
func (v *DAPSResponseInfoListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *DAPSResponseInfoListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoList")
	}
	bb.EnterComponent("DAPSResponseInfoList")
	value, err := BridgeUnmarshalAPERDAPSResponseInfoListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoList")
	}
	padding, err := aper.CaptureFinalBits(bb, "DAPSResponseInfoList")
	if err != nil {
		return runtime.WrapDecodePath(err, "DAPSResponseInfoList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERDAPSResponseInfoList encodes a DAPSResponseInfoList list to APER.
func BridgeMarshalAPERDAPSResponseInfoList(list DAPSResponseInfoListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERDAPSResponseInfoList decodes a DAPSResponseInfoList list from APER.
func BridgeUnmarshalAPERDAPSResponseInfoList(data []byte) (DAPSResponseInfoListComplete, error) {
	var value DAPSResponseInfoListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERDAPSResponseInfoListFrom decodes a DAPSResponseInfoList list from bb.
func BridgeUnmarshalAPERDAPSResponseInfoListFrom(bb *aper.BitBuffer) (s17.DAPSResponseInfoList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERDAPSResponseInfoListListValue
	if err := BridgeUnmarshalAPERDAPSResponseInfoListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERDAPSResponseInfoListInto(v *s25.BridgeAsn1cAPERDAPSResponseInfoListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.DAPSResponseInfoList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.DAPSResponseInfoListIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeDAPSResponseInfoListIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ECGIListComplete carries a complete ECGIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ECGIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.ECGIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ECGIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERECGIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ECGIList from APER format.
func (v *ECGIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECGIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECGIList")
	}
	bb.EnterComponent("ECGIList")
	value, err := BridgeUnmarshalAPERECGIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECGIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERECGIList encodes a ECGIList list to APER.
func BridgeMarshalAPERECGIList(list ECGIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERECGIList decodes a ECGIList list from APER.
func BridgeUnmarshalAPERECGIList(data []byte) (ECGIListComplete, error) {
	var value ECGIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERECGIListFrom decodes a ECGIList list from bb.
func BridgeUnmarshalAPERECGIListFrom(bb *aper.BitBuffer) (s20.ECGIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERECGIListListValue
	if err := BridgeUnmarshalAPERECGIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERECGIListInto(v *s25.BridgeAsn1cAPERECGIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.ECGIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CompletedCellinEAIComplete carries a complete CompletedCellinEAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CompletedCellinEAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CompletedCellinEAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CompletedCellinEAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCompletedCellinEAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CompletedCellinEAI from APER format.
func (v *CompletedCellinEAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CompletedCellinEAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAI")
	}
	bb.EnterComponent("CompletedCellinEAI")
	value, err := BridgeUnmarshalAPERCompletedCellinEAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CompletedCellinEAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinEAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCompletedCellinEAI encodes a CompletedCellinEAI list to APER.
func BridgeMarshalAPERCompletedCellinEAI(list CompletedCellinEAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCompletedCellinEAI decodes a CompletedCellinEAI list from APER.
func BridgeUnmarshalAPERCompletedCellinEAI(data []byte) (CompletedCellinEAIComplete, error) {
	var value CompletedCellinEAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCompletedCellinEAIFrom decodes a CompletedCellinEAI list from bb.
func BridgeUnmarshalAPERCompletedCellinEAIFrom(bb *aper.BitBuffer) (s20.CompletedCellinEAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCompletedCellinEAIListValue
	if err := BridgeUnmarshalAPERCompletedCellinEAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCompletedCellinEAIInto(v *s25.BridgeAsn1cAPERCompletedCellinEAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CompletedCellinEAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CompletedCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCompletedCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ENBX2TLAsComplete carries a complete ENBX2TLAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ENBX2TLAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ENBX2TLAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ENBX2TLAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERENBX2TLAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ENBX2TLAs from APER format.
func (v *ENBX2TLAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBX2TLAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBX2TLAs")
	}
	bb.EnterComponent("ENBX2TLAs")
	value, err := BridgeUnmarshalAPERENBX2TLAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2TLAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBX2TLAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2TLAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERENBX2TLAs encodes a ENBX2TLAs list to APER.
func BridgeMarshalAPERENBX2TLAs(list ENBX2TLAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERENBX2TLAs decodes a ENBX2TLAs list from APER.
func BridgeUnmarshalAPERENBX2TLAs(data []byte) (ENBX2TLAsComplete, error) {
	var value ENBX2TLAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERENBX2TLAsFrom decodes a ENBX2TLAs list from bb.
func BridgeUnmarshalAPERENBX2TLAsFrom(bb *aper.BitBuffer) (s00.ENBX2TLAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERENBX2TLAsListValue
	if err := BridgeUnmarshalAPERENBX2TLAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERENBX2TLAsInto(v *s00.BridgeAsn1cAPERENBX2TLAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ENBX2TLAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1201
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			elemBytes, elemBitLength, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, runtime.BitString{Bytes: elemBytes, BitLength: elemBitLength}); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// EPLMNsComplete carries a complete EPLMNs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type EPLMNsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.EPLMNs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *EPLMNsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPEREPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes EPLMNs from APER format.
func (v *EPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EPLMNsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EPLMNs")
	}
	bb.EnterComponent("EPLMNs")
	value, err := BridgeUnmarshalAPEREPLMNsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "EPLMNs")
	}
	padding, err := aper.CaptureFinalBits(bb, "EPLMNs")
	if err != nil {
		return runtime.WrapDecodePath(err, "EPLMNs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPEREPLMNs encodes a EPLMNs list to APER.
func BridgeMarshalAPEREPLMNs(list EPLMNsComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPEREPLMNs decodes a EPLMNs list from APER.
func BridgeUnmarshalAPEREPLMNs(data []byte) (EPLMNsComplete, error) {
	var value EPLMNsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPEREPLMNsFrom decodes a EPLMNs list from bb.
func BridgeUnmarshalAPEREPLMNsFrom(bb *aper.BitBuffer) (s00.EPLMNs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPEREPLMNsListValue
	if err := BridgeUnmarshalAPEREPLMNsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPEREPLMNsInto(v *s00.BridgeAsn1cAPEREPLMNsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.EPLMNs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ECGIListForRestartComplete carries a complete ECGIListForRestart encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ECGIListForRestartComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.ECGIListForRestart
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ECGIListForRestartComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERECGIListForRestartTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ECGIListForRestart from APER format.
func (v *ECGIListForRestartComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECGIListForRestartComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECGIListForRestart")
	}
	bb.EnterComponent("ECGIListForRestart")
	value, err := BridgeUnmarshalAPERECGIListForRestartFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGIListForRestart")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECGIListForRestart")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECGIListForRestart")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERECGIListForRestart encodes a ECGIListForRestart list to APER.
func BridgeMarshalAPERECGIListForRestart(list ECGIListForRestartComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERECGIListForRestart decodes a ECGIListForRestart list from APER.
func BridgeUnmarshalAPERECGIListForRestart(data []byte) (ECGIListForRestartComplete, error) {
	var value ECGIListForRestartComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERECGIListForRestartFrom decodes a ECGIListForRestart list from bb.
func BridgeUnmarshalAPERECGIListForRestartFrom(bb *aper.BitBuffer) (s20.ECGIListForRestart, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERECGIListForRestartListValue
	if err := BridgeUnmarshalAPERECGIListForRestartInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERECGIListForRestartInto(v *s25.BridgeAsn1cAPERECGIListForRestartListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.ECGIListForRestart, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CompletedCellinTAIComplete carries a complete CompletedCellinTAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CompletedCellinTAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.CompletedCellinTAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CompletedCellinTAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCompletedCellinTAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CompletedCellinTAI from APER format.
func (v *CompletedCellinTAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CompletedCellinTAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAI")
	}
	bb.EnterComponent("CompletedCellinTAI")
	value, err := BridgeUnmarshalAPERCompletedCellinTAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CompletedCellinTAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CompletedCellinTAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCompletedCellinTAI encodes a CompletedCellinTAI list to APER.
func BridgeMarshalAPERCompletedCellinTAI(list CompletedCellinTAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCompletedCellinTAI decodes a CompletedCellinTAI list from APER.
func BridgeUnmarshalAPERCompletedCellinTAI(data []byte) (CompletedCellinTAIComplete, error) {
	var value CompletedCellinTAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCompletedCellinTAIFrom decodes a CompletedCellinTAI list from bb.
func BridgeUnmarshalAPERCompletedCellinTAIFrom(bb *aper.BitBuffer) (s20.CompletedCellinTAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCompletedCellinTAIListValue
	if err := BridgeUnmarshalAPERCompletedCellinTAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCompletedCellinTAIInto(v *s25.BridgeAsn1cAPERCompletedCellinTAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.CompletedCellinTAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.CompletedCellinTAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeCompletedCellinTAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ENBX2ExtTLAsComplete carries a complete ENBX2ExtTLAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ENBX2ExtTLAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ENBX2ExtTLAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ENBX2ExtTLAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERENBX2ExtTLAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ENBX2ExtTLAs from APER format.
func (v *ENBX2ExtTLAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBX2ExtTLAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLAs")
	}
	bb.EnterComponent("ENBX2ExtTLAs")
	value, err := BridgeUnmarshalAPERENBX2ExtTLAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBX2ExtTLAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2ExtTLAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERENBX2ExtTLAs encodes a ENBX2ExtTLAs list to APER.
func BridgeMarshalAPERENBX2ExtTLAs(list ENBX2ExtTLAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERENBX2ExtTLAs decodes a ENBX2ExtTLAs list from APER.
func BridgeUnmarshalAPERENBX2ExtTLAs(data []byte) (ENBX2ExtTLAsComplete, error) {
	var value ENBX2ExtTLAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERENBX2ExtTLAsFrom decodes a ENBX2ExtTLAs list from bb.
func BridgeUnmarshalAPERENBX2ExtTLAsFrom(bb *aper.BitBuffer) (s18.ENBX2ExtTLAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERENBX2ExtTLAsListValue
	if err := BridgeUnmarshalAPERENBX2ExtTLAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERENBX2ExtTLAsInto(v *s25.BridgeAsn1cAPERENBX2ExtTLAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ENBX2ExtTLAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ENBX2ExtTLA
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeENBX2ExtTLAMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ENBX2GTPTLAsComplete carries a complete ENBX2GTPTLAs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ENBX2GTPTLAsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ENBX2GTPTLAs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ENBX2GTPTLAsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERENBX2GTPTLAsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ENBX2GTPTLAs from APER format.
func (v *ENBX2GTPTLAsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBX2GTPTLAsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBX2GTPTLAs")
	}
	bb.EnterComponent("ENBX2GTPTLAs")
	value, err := BridgeUnmarshalAPERENBX2GTPTLAsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2GTPTLAs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBX2GTPTLAs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBX2GTPTLAs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERENBX2GTPTLAs encodes a ENBX2GTPTLAs list to APER.
func BridgeMarshalAPERENBX2GTPTLAs(list ENBX2GTPTLAsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERENBX2GTPTLAs decodes a ENBX2GTPTLAs list from APER.
func BridgeUnmarshalAPERENBX2GTPTLAs(data []byte) (ENBX2GTPTLAsComplete, error) {
	var value ENBX2GTPTLAsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERENBX2GTPTLAsFrom decodes a ENBX2GTPTLAs list from bb.
func BridgeUnmarshalAPERENBX2GTPTLAsFrom(bb *aper.BitBuffer) (s00.ENBX2GTPTLAs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERENBX2GTPTLAsListValue
	if err := BridgeUnmarshalAPERENBX2GTPTLAsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERENBX2GTPTLAsInto(v *s00.BridgeAsn1cAPERENBX2GTPTLAsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ENBX2GTPTLAs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1201
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			elemBytes, elemBitLength, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, runtime.BitString{Bytes: elemBytes, BitLength: elemBitLength}); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ENBIndirectX2TransportLayerAddressesComplete carries a complete ENBIndirectX2TransportLayerAddresses encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ENBIndirectX2TransportLayerAddressesComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.ENBIndirectX2TransportLayerAddresses
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERENBIndirectX2TransportLayerAddressesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ENBIndirectX2TransportLayerAddresses from APER format.
func (v *ENBIndirectX2TransportLayerAddressesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBIndirectX2TransportLayerAddresses")
	}
	bb.EnterComponent("ENBIndirectX2TransportLayerAddresses")
	value, err := BridgeUnmarshalAPERENBIndirectX2TransportLayerAddressesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBIndirectX2TransportLayerAddresses")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBIndirectX2TransportLayerAddresses")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBIndirectX2TransportLayerAddresses")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERENBIndirectX2TransportLayerAddresses encodes a ENBIndirectX2TransportLayerAddresses list to APER.
func BridgeMarshalAPERENBIndirectX2TransportLayerAddresses(list ENBIndirectX2TransportLayerAddressesComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERENBIndirectX2TransportLayerAddresses decodes a ENBIndirectX2TransportLayerAddresses list from APER.
func BridgeUnmarshalAPERENBIndirectX2TransportLayerAddresses(data []byte) (ENBIndirectX2TransportLayerAddressesComplete, error) {
	var value ENBIndirectX2TransportLayerAddressesComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERENBIndirectX2TransportLayerAddressesFrom decodes a ENBIndirectX2TransportLayerAddresses list from bb.
func BridgeUnmarshalAPERENBIndirectX2TransportLayerAddressesFrom(bb *aper.BitBuffer) (s00.ENBIndirectX2TransportLayerAddresses, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERENBIndirectX2TransportLayerAddressesListValue
	if err := BridgeUnmarshalAPERENBIndirectX2TransportLayerAddressesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERENBIndirectX2TransportLayerAddressesInto(v *s00.BridgeAsn1cAPERENBIndirectX2TransportLayerAddressesListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.ENBIndirectX2TransportLayerAddresses, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1201
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			elemBytes, elemBitLength, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, runtime.BitString{Bytes: elemBytes, BitLength: elemBitLength}); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToEarlyStatusTransferListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToEarlyStatusTransferListComplete) WithoutReplay() BearersSubjectToEarlyStatusTransferListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToEarlyStatusTransferListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToStatusTransferListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToStatusTransferListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToStatusTransferListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToStatusTransferListComplete) WithoutReplay() BearersSubjectToStatusTransferListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToStatusTransferListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BluetoothMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BluetoothMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BluetoothMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BluetoothMeasConfigNameListComplete) WithoutReplay() BluetoothMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BluetoothMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CNTypeRestrictionsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CNTypeRestrictionsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CNTypeRestrictionsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CNTypeRestrictionsComplete) WithoutReplay() CNTypeRestrictionsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CNTypeRestrictionsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CSGIdListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGIdListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGIdListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGIdListComplete) WithoutReplay() CSGIdListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGIdListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinEAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinEAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinEAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinEAIComplete) WithoutReplay() CancelledCellinEAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinEAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinTAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinTAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinTAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinTAIComplete) WithoutReplay() CancelledCellinTAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinTAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDBroadcastComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDBroadcastComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDBroadcastComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDBroadcastComplete) WithoutReplay() CellIDBroadcastComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDBroadcastComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDCancelledComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDCancelledComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDCancelledComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDCancelledComplete) WithoutReplay() CellIDCancelledComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDCancelledComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIdListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIdListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIdListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIdListforMDTComplete) WithoutReplay() CellIdListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIdListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIdListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIdListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIdListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIdListforQMCComplete) WithoutReplay() CellIdListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIdListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CompletedCellinEAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CompletedCellinEAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CompletedCellinEAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CompletedCellinEAIComplete) WithoutReplay() CompletedCellinEAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CompletedCellinEAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CompletedCellinTAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CompletedCellinTAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CompletedCellinTAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CompletedCellinTAIComplete) WithoutReplay() CompletedCellinTAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CompletedCellinTAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ConnectedengNBListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ConnectedengNBListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ConnectedengNBListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ConnectedengNBListComplete) WithoutReplay() ConnectedengNBListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ConnectedengNBListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEListComplete) WithoutReplay() CriticalityDiagnosticsIEListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CriticalityDiagnosticsIEListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DAPSResponseInfoListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "DAPSResponseInfoListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DAPSResponseInfoListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DAPSResponseInfoListComplete) WithoutReplay() DAPSResponseInfoListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DAPSResponseInfoListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECGIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECGIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ECGIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECGIListComplete) WithoutReplay() ECGIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ECGIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECGIListForRestartComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECGIListForRestartComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ECGIListForRestartComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECGIListForRestartComplete) WithoutReplay() ECGIListForRestartComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ECGIListForRestartComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBIndirectX2TransportLayerAddressesComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBIndirectX2TransportLayerAddressesComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBIndirectX2TransportLayerAddressesComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBIndirectX2TransportLayerAddressesComplete) WithoutReplay() ENBIndirectX2TransportLayerAddressesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBIndirectX2TransportLayerAddressesComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBX2ExtTLAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBX2ExtTLAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBX2ExtTLAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBX2ExtTLAsComplete) WithoutReplay() ENBX2ExtTLAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBX2ExtTLAsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBX2GTPTLAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBX2GTPTLAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBX2GTPTLAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBX2GTPTLAsComplete) WithoutReplay() ENBX2GTPTLAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBX2GTPTLAsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBX2TLAsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBX2TLAsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBX2TLAsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBX2TLAsComplete) WithoutReplay() ENBX2TLAsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBX2TLAsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EPLMNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "EPLMNsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EPLMNsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EPLMNsComplete) WithoutReplay() EPLMNsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EPLMNsComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToEarlyStatusTransferListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToEarlyStatusTransferListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v, &s)
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
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToStatusTransferListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToStatusTransferListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v, &s)
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
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERBearersSubjectToStatusTransferListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BluetoothMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasConfigNameListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBluetoothMeasConfigNameListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BluetoothMeasConfigNameListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBluetoothMeasConfigNameListComplete(v, &s)
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
func (v *BluetoothMeasConfigNameListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERBluetoothMeasConfigNameListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CNTypeRestrictionsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CNTypeRestrictionsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CNTypeRestrictionsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCNTypeRestrictionsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CNTypeRestrictionsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CNTypeRestrictionsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
}
func (v *CNTypeRestrictionsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
}
func (v *CNTypeRestrictionsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCNTypeRestrictionsComplete(v, &s)
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
func (v *CNTypeRestrictionsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CNTypeRestrictionsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCNTypeRestrictionsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CSGIdListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGIdListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGIdListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGIdListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGIdListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGIdListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGIdListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGIdListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGIdListComplete")
}
func (v *CSGIdListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGIdListComplete")
}
func (v *CSGIdListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGIdListComplete(v, &s)
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
func (v *CSGIdListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGIdListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCSGIdListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CancelledCellinEAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinEAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinEAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinEAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinEAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinEAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinEAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinEAIComplete")
}
func (v *CancelledCellinEAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinEAIComplete")
}
func (v *CancelledCellinEAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinEAIComplete(v, &s)
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
func (v *CancelledCellinEAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinEAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCancelledCellinEAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CancelledCellinTAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinTAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinTAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinTAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinTAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinTAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinTAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinTAIComplete")
}
func (v *CancelledCellinTAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinTAIComplete")
}
func (v *CancelledCellinTAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinTAIComplete(v, &s)
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
func (v *CancelledCellinTAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinTAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCancelledCellinTAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIDBroadcastComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDBroadcastComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDBroadcastComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDBroadcastComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDBroadcastComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDBroadcastComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDBroadcastComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDBroadcastComplete")
}
func (v *CellIDBroadcastComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDBroadcastComplete")
}
func (v *CellIDBroadcastComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDBroadcastComplete(v, &s)
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
func (v *CellIDBroadcastComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDBroadcastComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCellIDBroadcastTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIDCancelledComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDCancelledComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDCancelledComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDCancelledComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDCancelledComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDCancelledComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDCancelledComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDCancelledComplete")
}
func (v *CellIDCancelledComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDCancelledComplete")
}
func (v *CellIDCancelledComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDCancelledComplete(v, &s)
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
func (v *CellIDCancelledComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDCancelledComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCellIDCancelledTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIdListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIdListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIdListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIdListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIdListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIdListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIdListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIdListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIdListforMDTComplete")
}
func (v *CellIdListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIdListforMDTComplete")
}
func (v *CellIdListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIdListforMDTComplete(v, &s)
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
func (v *CellIdListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIdListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCellIdListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIdListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIdListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIdListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIdListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIdListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIdListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIdListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIdListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIdListforQMCComplete")
}
func (v *CellIdListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIdListforQMCComplete")
}
func (v *CellIdListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIdListforQMCComplete(v, &s)
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
func (v *CellIdListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIdListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCellIdListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CompletedCellinEAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CompletedCellinEAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CompletedCellinEAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinEAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCompletedCellinEAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CompletedCellinEAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CompletedCellinEAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CompletedCellinEAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CompletedCellinEAIComplete")
}
func (v *CompletedCellinEAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CompletedCellinEAIComplete")
}
func (v *CompletedCellinEAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCompletedCellinEAIComplete(v, &s)
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
func (v *CompletedCellinEAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CompletedCellinEAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCompletedCellinEAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CompletedCellinTAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CompletedCellinTAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CompletedCellinTAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinTAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCompletedCellinTAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CompletedCellinTAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CompletedCellinTAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CompletedCellinTAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CompletedCellinTAIComplete")
}
func (v *CompletedCellinTAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CompletedCellinTAIComplete")
}
func (v *CompletedCellinTAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCompletedCellinTAIComplete(v, &s)
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
func (v *CompletedCellinTAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CompletedCellinTAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCompletedCellinTAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ConnectedengNBListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ConnectedengNBListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ConnectedengNBListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APConnectedengNBListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ConnectedengNBListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ConnectedengNBListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ConnectedengNBListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ConnectedengNBListComplete")
}
func (v *ConnectedengNBListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ConnectedengNBListComplete")
}
func (v *ConnectedengNBListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APConnectedengNBListComplete(v, &s)
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
func (v *ConnectedengNBListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ConnectedengNBListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s40.BridgeMarshalAPERConnectedengNBListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CriticalityDiagnosticsIEListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCriticalityDiagnosticsIEListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CriticalityDiagnosticsIEListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCriticalityDiagnosticsIEListComplete(v, &s)
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
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *DAPSResponseInfoListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DAPSResponseInfoListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DAPSResponseInfoListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDAPSResponseInfoListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DAPSResponseInfoListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DAPSResponseInfoListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DAPSResponseInfoListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DAPSResponseInfoListComplete")
}
func (v *DAPSResponseInfoListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DAPSResponseInfoListComplete")
}
func (v *DAPSResponseInfoListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDAPSResponseInfoListComplete(v, &s)
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
func (v *DAPSResponseInfoListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DAPSResponseInfoListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERDAPSResponseInfoListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ECGIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ECGIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ECGIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECGIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APECGIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ECGIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ECGIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ECGIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ECGIListComplete")
}
func (v *ECGIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ECGIListComplete")
}
func (v *ECGIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APECGIListComplete(v, &s)
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
func (v *ECGIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ECGIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERECGIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ECGIListForRestartComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ECGIListForRestartComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ECGIListForRestartComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECGIListForRestartComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APECGIListForRestartComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ECGIListForRestartComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ECGIListForRestartComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ECGIListForRestartComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ECGIListForRestartComplete")
}
func (v *ECGIListForRestartComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ECGIListForRestartComplete")
}
func (v *ECGIListForRestartComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APECGIListForRestartComplete(v, &s)
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
func (v *ECGIListForRestartComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ECGIListForRestartComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERECGIListForRestartTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBIndirectX2TransportLayerAddressesComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBIndirectX2TransportLayerAddressesComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBIndirectX2TransportLayerAddressesComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBIndirectX2TransportLayerAddressesComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBIndirectX2TransportLayerAddressesComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBIndirectX2TransportLayerAddressesComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBIndirectX2TransportLayerAddressesComplete")
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBIndirectX2TransportLayerAddressesComplete")
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBIndirectX2TransportLayerAddressesComplete(v, &s)
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
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBIndirectX2TransportLayerAddressesComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERENBIndirectX2TransportLayerAddressesTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBX2ExtTLAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBX2ExtTLAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBX2ExtTLAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBX2ExtTLAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBX2ExtTLAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBX2ExtTLAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBX2ExtTLAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBX2ExtTLAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBX2ExtTLAsComplete")
}
func (v *ENBX2ExtTLAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBX2ExtTLAsComplete")
}
func (v *ENBX2ExtTLAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBX2ExtTLAsComplete(v, &s)
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
func (v *ENBX2ExtTLAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBX2ExtTLAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERENBX2ExtTLAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBX2GTPTLAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBX2GTPTLAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBX2GTPTLAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBX2GTPTLAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBX2GTPTLAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBX2GTPTLAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBX2GTPTLAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBX2GTPTLAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBX2GTPTLAsComplete")
}
func (v *ENBX2GTPTLAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBX2GTPTLAsComplete")
}
func (v *ENBX2GTPTLAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBX2GTPTLAsComplete(v, &s)
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
func (v *ENBX2GTPTLAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBX2GTPTLAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERENBX2GTPTLAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBX2TLAsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBX2TLAsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBX2TLAsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBX2TLAsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBX2TLAsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBX2TLAsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBX2TLAsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBX2TLAsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBX2TLAsComplete")
}
func (v *ENBX2TLAsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBX2TLAsComplete")
}
func (v *ENBX2TLAsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBX2TLAsComplete(v, &s)
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
func (v *ENBX2TLAsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBX2TLAsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPERENBX2TLAsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *EPLMNsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EPLMNsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *EPLMNsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EPLMNsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APEPLMNsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "EPLMNsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "EPLMNsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *EPLMNsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "EPLMNsComplete")
}
func (v *EPLMNsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "EPLMNsComplete")
}
func (v *EPLMNsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APEPLMNsComplete(v, &s)
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
func (v *EPLMNsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *EPLMNsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s16.BridgeMarshalAPEREPLMNsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToEarlyStatusTransferListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToEarlyStatusTransferListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToEarlyStatusTransferListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToEarlyStatusTransferListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToEarlyStatusTransferListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToStatusTransferListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToStatusTransferListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToStatusTransferListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToStatusTransferListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToStatusTransferListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BluetoothMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasConfigNameListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BluetoothMeasConfigNameListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBluetoothMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BluetoothMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BluetoothMeasConfigNameListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CNTypeRestrictionsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CNTypeRestrictionsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCNTypeRestrictionsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CNTypeRestrictionsComplete{}
		return report, aper.OperationError(err, "CNTypeRestrictionsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CNTypeRestrictionsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CSGIdListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGIdListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGIdListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGIdListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGIdListComplete{}
		return report, aper.OperationError(err, "CSGIdListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGIdListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinEAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinEAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinEAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinEAIComplete{}
		return report, aper.OperationError(err, "CancelledCellinEAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinEAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinTAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinTAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinTAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinTAIComplete{}
		return report, aper.OperationError(err, "CancelledCellinTAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinTAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDBroadcastComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDBroadcastComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDBroadcastComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDBroadcastComplete{}
		return report, aper.OperationError(err, "CellIDBroadcastComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDBroadcastComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDCancelledComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDCancelledComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDCancelledComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDCancelledComplete{}
		return report, aper.OperationError(err, "CellIDCancelledComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDCancelledComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIdListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIdListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIdListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIdListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIdListforMDTComplete{}
		return report, aper.OperationError(err, "CellIdListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIdListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIdListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIdListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIdListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIdListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIdListforQMCComplete{}
		return report, aper.OperationError(err, "CellIdListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIdListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CompletedCellinEAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinEAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CompletedCellinEAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCompletedCellinEAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CompletedCellinEAIComplete{}
		return report, aper.OperationError(err, "CompletedCellinEAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CompletedCellinEAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CompletedCellinTAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CompletedCellinTAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CompletedCellinTAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCompletedCellinTAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CompletedCellinTAIComplete{}
		return report, aper.OperationError(err, "CompletedCellinTAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CompletedCellinTAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ConnectedengNBListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ConnectedengNBListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ConnectedengNBListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APConnectedengNBListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ConnectedengNBListComplete{}
		return report, aper.OperationError(err, "ConnectedengNBListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ConnectedengNBListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CriticalityDiagnosticsIEListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CriticalityDiagnosticsIEListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCriticalityDiagnosticsIEListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEListComplete{}
		return report, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnosticsIEListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *DAPSResponseInfoListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DAPSResponseInfoListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DAPSResponseInfoListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDAPSResponseInfoListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DAPSResponseInfoListComplete{}
		return report, aper.OperationError(err, "DAPSResponseInfoListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DAPSResponseInfoListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ECGIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECGIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ECGIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APECGIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ECGIListComplete{}
		return report, aper.OperationError(err, "ECGIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECGIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ECGIListForRestartComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECGIListForRestartComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ECGIListForRestartComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APECGIListForRestartComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ECGIListForRestartComplete{}
		return report, aper.OperationError(err, "ECGIListForRestartComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECGIListForRestartComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBIndirectX2TransportLayerAddressesComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBIndirectX2TransportLayerAddressesComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBIndirectX2TransportLayerAddressesComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBIndirectX2TransportLayerAddressesComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBIndirectX2TransportLayerAddressesComplete{}
		return report, aper.OperationError(err, "ENBIndirectX2TransportLayerAddressesComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBIndirectX2TransportLayerAddressesComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBX2ExtTLAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBX2ExtTLAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBX2ExtTLAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBX2ExtTLAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBX2ExtTLAsComplete{}
		return report, aper.OperationError(err, "ENBX2ExtTLAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBX2ExtTLAsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBX2GTPTLAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBX2GTPTLAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBX2GTPTLAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBX2GTPTLAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBX2GTPTLAsComplete{}
		return report, aper.OperationError(err, "ENBX2GTPTLAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBX2GTPTLAsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBX2TLAsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBX2TLAsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBX2TLAsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBX2TLAsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBX2TLAsComplete{}
		return report, aper.OperationError(err, "ENBX2TLAsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBX2TLAsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *EPLMNsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EPLMNsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded EPLMNsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APEPLMNsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = EPLMNsComplete{}
		return report, aper.OperationError(err, "EPLMNsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EPLMNsComplete")
}

// MarshalAPERBearersSubjectToStatusTransferList encodes a complete named list.
func MarshalAPERBearersSubjectToStatusTransferList(v BearersSubjectToStatusTransferListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBearersSubjectToEarlyStatusTransferList encodes a complete named list.
func MarshalAPERBearersSubjectToEarlyStatusTransferList(v BearersSubjectToEarlyStatusTransferListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBluetoothMeasConfigNameList encodes a complete named list.
func MarshalAPERBluetoothMeasConfigNameList(v BluetoothMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCancelledCellinEAI encodes a complete named list.
func MarshalAPERCancelledCellinEAI(v CancelledCellinEAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCancelledCellinTAI encodes a complete named list.
func MarshalAPERCancelledCellinTAI(v CancelledCellinTAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIDBroadcast encodes a complete named list.
func MarshalAPERCellIDBroadcast(v CellIDBroadcastComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIDCancelled encodes a complete named list.
func MarshalAPERCellIDCancelled(v CellIDCancelledComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIdListforMDT encodes a complete named list.
func MarshalAPERCellIdListforMDT(v CellIdListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIdListforQMC encodes a complete named list.
func MarshalAPERCellIdListforQMC(v CellIdListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCNTypeRestrictions encodes a complete named list.
func MarshalAPERCNTypeRestrictions(v CNTypeRestrictionsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERConnectedengNBList encodes a complete named list.
func MarshalAPERConnectedengNBList(v ConnectedengNBListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCSGIdList encodes a complete named list.
func MarshalAPERCSGIdList(v CSGIdListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a complete named list.
func MarshalAPERCriticalityDiagnosticsIEList(v CriticalityDiagnosticsIEListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERDAPSResponseInfoList encodes a complete named list.
func MarshalAPERDAPSResponseInfoList(v DAPSResponseInfoListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERECGIList encodes a complete named list.
func MarshalAPERECGIList(v ECGIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCompletedCellinEAI encodes a complete named list.
func MarshalAPERCompletedCellinEAI(v CompletedCellinEAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERENBX2TLAs encodes a complete named list.
func MarshalAPERENBX2TLAs(v ENBX2TLAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPEREPLMNs encodes a complete named list.
func MarshalAPEREPLMNs(v EPLMNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERECGIListForRestart encodes a complete named list.
func MarshalAPERECGIListForRestart(v ECGIListForRestartComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCompletedCellinTAI encodes a complete named list.
func MarshalAPERCompletedCellinTAI(v CompletedCellinTAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERENBX2ExtTLAs encodes a complete named list.
func MarshalAPERENBX2ExtTLAs(v ENBX2ExtTLAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERENBX2GTPTLAs encodes a complete named list.
func MarshalAPERENBX2GTPTLAs(v ENBX2GTPTLAsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERENBIndirectX2TransportLayerAddresses encodes a complete named list.
func MarshalAPERENBIndirectX2TransportLayerAddresses(v ENBIndirectX2TransportLayerAddressesComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERBearersSubjectToStatusTransferList decodes a complete named list.
func UnmarshalAPERBearersSubjectToStatusTransferList(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToStatusTransferListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferList decodes a complete named list.
func UnmarshalAPERBearersSubjectToEarlyStatusTransferList(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToEarlyStatusTransferListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBluetoothMeasConfigNameList decodes a complete named list.
func UnmarshalAPERBluetoothMeasConfigNameList(data []byte, options ...aper.DecodeOption) (BluetoothMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v BluetoothMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCancelledCellinEAI decodes a complete named list.
func UnmarshalAPERCancelledCellinEAI(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIComplete, aper.DecodeReport, error) {
	var v CancelledCellinEAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCancelledCellinTAI decodes a complete named list.
func UnmarshalAPERCancelledCellinTAI(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIComplete, aper.DecodeReport, error) {
	var v CancelledCellinTAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIDBroadcast decodes a complete named list.
func UnmarshalAPERCellIDBroadcast(data []byte, options ...aper.DecodeOption) (CellIDBroadcastComplete, aper.DecodeReport, error) {
	var v CellIDBroadcastComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIDCancelled decodes a complete named list.
func UnmarshalAPERCellIDCancelled(data []byte, options ...aper.DecodeOption) (CellIDCancelledComplete, aper.DecodeReport, error) {
	var v CellIDCancelledComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIdListforMDT decodes a complete named list.
func UnmarshalAPERCellIdListforMDT(data []byte, options ...aper.DecodeOption) (CellIdListforMDTComplete, aper.DecodeReport, error) {
	var v CellIdListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIdListforQMC decodes a complete named list.
func UnmarshalAPERCellIdListforQMC(data []byte, options ...aper.DecodeOption) (CellIdListforQMCComplete, aper.DecodeReport, error) {
	var v CellIdListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCNTypeRestrictions decodes a complete named list.
func UnmarshalAPERCNTypeRestrictions(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsComplete, aper.DecodeReport, error) {
	var v CNTypeRestrictionsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERConnectedengNBList decodes a complete named list.
func UnmarshalAPERConnectedengNBList(data []byte, options ...aper.DecodeOption) (ConnectedengNBListComplete, aper.DecodeReport, error) {
	var v ConnectedengNBListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCSGIdList decodes a complete named list.
func UnmarshalAPERCSGIdList(data []byte, options ...aper.DecodeOption) (CSGIdListComplete, aper.DecodeReport, error) {
	var v CSGIdListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a complete named list.
func UnmarshalAPERCriticalityDiagnosticsIEList(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListComplete, aper.DecodeReport, error) {
	var v CriticalityDiagnosticsIEListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERDAPSResponseInfoList decodes a complete named list.
func UnmarshalAPERDAPSResponseInfoList(data []byte, options ...aper.DecodeOption) (DAPSResponseInfoListComplete, aper.DecodeReport, error) {
	var v DAPSResponseInfoListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERECGIList decodes a complete named list.
func UnmarshalAPERECGIList(data []byte, options ...aper.DecodeOption) (ECGIListComplete, aper.DecodeReport, error) {
	var v ECGIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCompletedCellinEAI decodes a complete named list.
func UnmarshalAPERCompletedCellinEAI(data []byte, options ...aper.DecodeOption) (CompletedCellinEAIComplete, aper.DecodeReport, error) {
	var v CompletedCellinEAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERENBX2TLAs decodes a complete named list.
func UnmarshalAPERENBX2TLAs(data []byte, options ...aper.DecodeOption) (ENBX2TLAsComplete, aper.DecodeReport, error) {
	var v ENBX2TLAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPEREPLMNs decodes a complete named list.
func UnmarshalAPEREPLMNs(data []byte, options ...aper.DecodeOption) (EPLMNsComplete, aper.DecodeReport, error) {
	var v EPLMNsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERECGIListForRestart decodes a complete named list.
func UnmarshalAPERECGIListForRestart(data []byte, options ...aper.DecodeOption) (ECGIListForRestartComplete, aper.DecodeReport, error) {
	var v ECGIListForRestartComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCompletedCellinTAI decodes a complete named list.
func UnmarshalAPERCompletedCellinTAI(data []byte, options ...aper.DecodeOption) (CompletedCellinTAIComplete, aper.DecodeReport, error) {
	var v CompletedCellinTAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERENBX2ExtTLAs decodes a complete named list.
func UnmarshalAPERENBX2ExtTLAs(data []byte, options ...aper.DecodeOption) (ENBX2ExtTLAsComplete, aper.DecodeReport, error) {
	var v ENBX2ExtTLAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERENBX2GTPTLAs decodes a complete named list.
func UnmarshalAPERENBX2GTPTLAs(data []byte, options ...aper.DecodeOption) (ENBX2GTPTLAsComplete, aper.DecodeReport, error) {
	var v ENBX2GTPTLAsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERENBIndirectX2TransportLayerAddresses decodes a complete named list.
func UnmarshalAPERENBIndirectX2TransportLayerAddresses(data []byte, options ...aper.DecodeOption) (ENBIndirectX2TransportLayerAddressesComplete, aper.DecodeReport, error) {
	var v ENBIndirectX2TransportLayerAddressesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// MMEEarlyStatusTransfer represents the ASN.1 type MMEEarlyStatusTransfer (SEQUENCE).
type MMEEarlyStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s47.MMEEarlyStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextResumeRequest represents the ASN.1 type UEContextResumeRequest (SEQUENCE).
type UEContextResumeRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      UEContextResumeRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ERABAdmittedListComplete carries a complete ERABAdmittedList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABAdmittedListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ERABAdmittedList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABAdmittedListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABAdmittedListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABAdmittedList from APER format.
func (v *ERABAdmittedListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABAdmittedListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedList")
	}
	bb.EnterComponent("ERABAdmittedList")
	value, err := BridgeUnmarshalAPERERABAdmittedListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABAdmittedList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABAdmittedList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABAdmittedList encodes a ERABAdmittedList list to APER.
func BridgeMarshalAPERERABAdmittedList(list ERABAdmittedListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABAdmittedList decodes a ERABAdmittedList list from APER.
func BridgeUnmarshalAPERERABAdmittedList(data []byte) (ERABAdmittedListComplete, error) {
	var value ERABAdmittedListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABAdmittedListFrom decodes a ERABAdmittedList list from bb.
func BridgeUnmarshalAPERERABAdmittedListFrom(bb *aper.BitBuffer) (s18.ERABAdmittedList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERERABAdmittedListListValue
	if err := BridgeUnmarshalAPERERABAdmittedListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABAdmittedListInto(v *s25.BridgeAsn1cAPERERABAdmittedListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ERABAdmittedList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ERABAdmittedItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeERABAdmittedItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes MMEEarlyStatusTransfer to APER format.
func (v *MMEEarlyStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEEarlyStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes MMEEarlyStatusTransfer from APER format.
func (v *MMEEarlyStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MMEEarlyStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	bb.EnterComponent("MMEEarlyStatusTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	v.perPadding = padding
	return nil
}
func (v *MMEEarlyStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEEarlyStatusTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s47.MMEEarlyStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s47.MMEEarlyStatusTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextResumeRequest to APER format.
func (v *UEContextResumeRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextResumeRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes UEContextResumeRequest from APER format.
func (v *UEContextResumeRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEContextResumeRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeRequest")
	}
	bb.EnterComponent("UEContextResumeRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextResumeRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *UEContextResumeRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(UEContextResumeRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem UEContextResumeRequestIEField
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

// ERABFailedToResumeListResumeReqComplete carries a complete ERABFailedToResumeListResumeReq encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABFailedToResumeListResumeReqComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ERABFailedToResumeListResumeReq
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABFailedToResumeListResumeReqTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABFailedToResumeListResumeReq from APER format.
func (v *ERABFailedToResumeListResumeReqComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABFailedToResumeListResumeReqComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
	}
	bb.EnterComponent("ERABFailedToResumeListResumeReq")
	value, err := BridgeUnmarshalAPERERABFailedToResumeListResumeReqFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeListResumeReq")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERERABFailedToResumeListResumeReq encodes a ERABFailedToResumeListResumeReq list to APER.
func BridgeMarshalAPERERABFailedToResumeListResumeReq(list ERABFailedToResumeListResumeReqComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERERABFailedToResumeListResumeReq decodes a ERABFailedToResumeListResumeReq list from APER.
func BridgeUnmarshalAPERERABFailedToResumeListResumeReq(data []byte) (ERABFailedToResumeListResumeReqComplete, error) {
	var value ERABFailedToResumeListResumeReqComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERERABFailedToResumeListResumeReqFrom decodes a ERABFailedToResumeListResumeReq list from bb.
func BridgeUnmarshalAPERERABFailedToResumeListResumeReqFrom(bb *aper.BitBuffer) (s18.ERABFailedToResumeListResumeReq, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue
	if err := BridgeUnmarshalAPERERABFailedToResumeListResumeReqInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABFailedToResumeListResumeReqInto(v *s25.BridgeAsn1cAPERERABFailedToResumeListResumeReqListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ERABFailedToResumeListResumeReq, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ERABFailedToResumeItemResumeReqIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeERABFailedToResumeItemResumeReqIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ERABFailedToResumeListResumeResComplete carries a complete ERABFailedToResumeListResumeRes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ERABFailedToResumeListResumeResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.ERABFailedToResumeListResumeRes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ERABFailedToResumeListResumeResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERERABFailedToResumeListResumeResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ERABFailedToResumeListResumeRes from APER format.
func (v *ERABFailedToResumeListResumeResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ERABFailedToResumeListResumeResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeRes")
	}
	bb.EnterComponent("ERABFailedToResumeListResumeRes")
	value, err := BridgeUnmarshalAPERERABFailedToResumeListResumeResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "ERABFailedToResumeListResumeRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeRes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// UnmarshalAPERERABFailedToResumeListResumeResFrom decodes a ERABFailedToResumeListResumeRes list from bb.
func BridgeUnmarshalAPERERABFailedToResumeListResumeResFrom(bb *aper.BitBuffer) (s18.ERABFailedToResumeListResumeRes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERERABFailedToResumeListResumeResListValue
	if err := BridgeUnmarshalAPERERABFailedToResumeListResumeResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERERABFailedToResumeListResumeResInto(v *s25.BridgeAsn1cAPERERABFailedToResumeListResumeResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.ERABFailedToResumeListResumeRes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.ERABFailedToResumeItemResumeResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeERABFailedToResumeItemResumeResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABAdmittedListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABAdmittedListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABAdmittedListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABAdmittedListComplete) WithoutReplay() ERABAdmittedListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABAdmittedListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABFailedToResumeListResumeReqComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedToResumeListResumeReqComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedToResumeListResumeReqComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedToResumeListResumeReqComplete) WithoutReplay() ERABFailedToResumeListResumeReqComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedToResumeListResumeReqComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ERABFailedToResumeListResumeResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ERABFailedToResumeListResumeResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ERABFailedToResumeListResumeResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ERABFailedToResumeListResumeResComplete) WithoutReplay() ERABFailedToResumeListResumeResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ERABFailedToResumeListResumeResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEEarlyStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEEarlyStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEEarlyStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEEarlyStatusTransfer) WithoutReplay() MMEEarlyStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEEarlyStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextResumeRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextResumeRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextResumeRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextResumeRequest) WithoutReplay() UEContextResumeRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextResumeRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *MMEEarlyStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEEarlyStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEEarlyStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextResumeRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextResumeRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextResumeRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextResumeRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextResumeRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextResumeRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextResumeRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABAdmittedListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABAdmittedListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABAdmittedListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABAdmittedListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABAdmittedListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABAdmittedListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABAdmittedListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABAdmittedListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABAdmittedListComplete")
}
func (v *ERABAdmittedListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABAdmittedListComplete")
}
func (v *ERABAdmittedListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABAdmittedListComplete(v, &s)
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
func (v *ERABAdmittedListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABAdmittedListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABAdmittedListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABFailedToResumeListResumeReqComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedToResumeListResumeReqComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeListResumeReqComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedToResumeListResumeReqComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedToResumeListResumeReqComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedToResumeListResumeReqComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedToResumeListResumeReqComplete")
}
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedToResumeListResumeReqComplete")
}
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedToResumeListResumeReqComplete(v, &s)
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
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedToResumeListResumeReqComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABFailedToResumeListResumeReqTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ERABFailedToResumeListResumeResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ERABFailedToResumeListResumeResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeListResumeResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APERABFailedToResumeListResumeResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ERABFailedToResumeListResumeResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ERABFailedToResumeListResumeResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ERABFailedToResumeListResumeResComplete")
}
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ERABFailedToResumeListResumeResComplete")
}
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APERABFailedToResumeListResumeResComplete(v, &s)
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
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ERABFailedToResumeListResumeResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERERABFailedToResumeListResumeResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *MMEEarlyStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEEarlyStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEEarlyStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEEarlyStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEEarlyStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEEarlyStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func (v *MMEEarlyStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func (v *MMEEarlyStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEEarlyStatusTransfer(v, &s)
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
func (v *MMEEarlyStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEEarlyStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextResumeRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextResumeRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextResumeRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextResumeRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextResumeRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextResumeRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextResumeRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextResumeRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextResumeRequest")
}
func (v *UEContextResumeRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextResumeRequest")
}
func (v *UEContextResumeRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextResumeRequest(v, &s)
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
func (v *UEContextResumeRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextResumeRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ERABAdmittedListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABAdmittedListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABAdmittedListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABAdmittedListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABAdmittedListComplete{}
		return report, aper.OperationError(err, "ERABAdmittedListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABAdmittedListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABFailedToResumeListResumeReqComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeListResumeReqComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedToResumeListResumeReqComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedToResumeListResumeReqComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedToResumeListResumeReqComplete{}
		return report, aper.OperationError(err, "ERABFailedToResumeListResumeReqComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedToResumeListResumeReqComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ERABFailedToResumeListResumeResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ERABFailedToResumeListResumeResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ERABFailedToResumeListResumeResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APERABFailedToResumeListResumeResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ERABFailedToResumeListResumeResComplete{}
		return report, aper.OperationError(err, "ERABFailedToResumeListResumeResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ERABFailedToResumeListResumeResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEEarlyStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEEarlyStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEEarlyStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEEarlyStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEEarlyStatusTransfer{}
		return report, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEEarlyStatusTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextResumeRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextResumeRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextResumeRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextResumeRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextResumeRequest{}
		return report, aper.OperationError(err, "UEContextResumeRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextResumeRequest")
}

// MarshalAPERERABAdmittedList encodes a complete named list.
func MarshalAPERERABAdmittedList(v ERABAdmittedListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABFailedToResumeListResumeReq encodes a complete named list.
func MarshalAPERERABFailedToResumeListResumeReq(v ERABFailedToResumeListResumeReqComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERERABFailedToResumeListResumeRes encodes a complete named list.
func MarshalAPERERABFailedToResumeListResumeRes(v ERABFailedToResumeListResumeResComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERERABAdmittedList decodes a complete named list.
func UnmarshalAPERERABAdmittedList(data []byte, options ...aper.DecodeOption) (ERABAdmittedListComplete, aper.DecodeReport, error) {
	var v ERABAdmittedListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERERABFailedToResumeListResumeReq decodes a complete named list.
func UnmarshalAPERERABFailedToResumeListResumeReq(data []byte, options ...aper.DecodeOption) (ERABFailedToResumeListResumeReqComplete, aper.DecodeReport, error) {
	var v ERABFailedToResumeListResumeReqComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// CandidateCellListComplete carries a complete CandidateCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidateCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s21.CandidateCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CandidateCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCandidateCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CandidateCellList from APER format.
func (v *CandidateCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CandidateCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	bb.EnterComponent("CandidateCellList")
	value, err := BridgeUnmarshalAPERCandidateCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidateCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCandidateCellList encodes a CandidateCellList list to APER.
func BridgeMarshalAPERCandidateCellList(list CandidateCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCandidateCellList decodes a CandidateCellList list from APER.
func BridgeUnmarshalAPERCandidateCellList(data []byte) (CandidateCellListComplete, error) {
	var value CandidateCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCandidateCellListFrom decodes a CandidateCellList list from bb.
func BridgeUnmarshalAPERCandidateCellListFrom(bb *aper.BitBuffer) (s21.CandidateCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCandidateCellListListValue
	if err := BridgeUnmarshalAPERCandidateCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCandidateCellListInto(v *s25.BridgeAsn1cAPERCandidateCellListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s21.CandidateCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s21.IRATCellID
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s21.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CandidatePCIListComplete carries a complete CandidatePCIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidatePCIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CandidatePCIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CandidatePCIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCandidatePCIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CandidatePCIList from APER format.
func (v *CandidatePCIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CandidatePCIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	bb.EnterComponent("CandidatePCIList")
	value, err := BridgeUnmarshalAPERCandidatePCIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidatePCIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCandidatePCIList encodes a CandidatePCIList list to APER.
func BridgeMarshalAPERCandidatePCIList(list CandidatePCIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCandidatePCIList decodes a CandidatePCIList list from APER.
func BridgeUnmarshalAPERCandidatePCIList(data []byte) (CandidatePCIListComplete, error) {
	var value CandidatePCIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCandidatePCIListFrom decodes a CandidatePCIList list from bb.
func BridgeUnmarshalAPERCandidatePCIListFrom(bb *aper.BitBuffer) (s17.CandidatePCIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCandidatePCIListListValue
	if err := BridgeUnmarshalAPERCandidatePCIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCandidatePCIListInto(v *s25.BridgeAsn1cAPERCandidatePCIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CandidatePCIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CandidatePCI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCandidatePCIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellsToActivateListComplete carries a complete CellsToActivateList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellsToActivateListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CellsToActivateList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellsToActivateListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERCellsToActivateListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellsToActivateList from APER format.
func (v *CellsToActivateListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CellsToActivateListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	bb.EnterComponent("CellsToActivateList")
	value, err := BridgeUnmarshalAPERCellsToActivateListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellsToActivateList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellsToActivateList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellsToActivateList encodes a CellsToActivateList list to APER.
func BridgeMarshalAPERCellsToActivateList(list CellsToActivateListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellsToActivateList decodes a CellsToActivateList list from APER.
func BridgeUnmarshalAPERCellsToActivateList(data []byte) (CellsToActivateListComplete, error) {
	var value CellsToActivateListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellsToActivateListFrom decodes a CellsToActivateList list from bb.
func BridgeUnmarshalAPERCellsToActivateListFrom(bb *aper.BitBuffer) (s17.CellsToActivateList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERCellsToActivateListListValue
	if err := BridgeUnmarshalAPERCellsToActivateListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellsToActivateListInto(v *s25.BridgeAsn1cAPERCellsToActivateListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CellsToActivateList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CellsToActivateListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCellsToActivateListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CandidateCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidateCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidateCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidateCellListComplete) WithoutReplay() CandidateCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidateCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CandidatePCIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidatePCIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidatePCIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidatePCIListComplete) WithoutReplay() CandidatePCIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidatePCIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellsToActivateListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellsToActivateListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellsToActivateListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellsToActivateListComplete) WithoutReplay() CellsToActivateListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellsToActivateListComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CandidateCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidateCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidateCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidateCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidateCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidateCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidateCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidateCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidateCellListComplete")
}
func (v *CandidateCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidateCellListComplete")
}
func (v *CandidateCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidateCellListComplete(v, &s)
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
func (v *CandidateCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidateCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCandidateCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CandidatePCIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidatePCIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidatePCIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidatePCIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidatePCIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidatePCIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidatePCIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidatePCIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidatePCIListComplete")
}
func (v *CandidatePCIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidatePCIListComplete")
}
func (v *CandidatePCIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidatePCIListComplete(v, &s)
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
func (v *CandidatePCIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidatePCIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCandidatePCIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellsToActivateListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellsToActivateListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellsToActivateListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellsToActivateListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellsToActivateListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellsToActivateListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellsToActivateListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellsToActivateListComplete")
}
func (v *CellsToActivateListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellsToActivateListComplete")
}
func (v *CellsToActivateListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellsToActivateListComplete(v, &s)
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
func (v *CellsToActivateListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellsToActivateListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERCellsToActivateListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CandidateCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidateCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidateCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidateCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidateCellListComplete{}
		return report, aper.OperationError(err, "CandidateCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidateCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CandidatePCIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidatePCIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidatePCIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidatePCIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidatePCIListComplete{}
		return report, aper.OperationError(err, "CandidatePCIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidatePCIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellsToActivateListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellsToActivateListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellsToActivateListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellsToActivateListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellsToActivateListComplete{}
		return report, aper.OperationError(err, "CellsToActivateListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellsToActivateListComplete")
}

// MarshalAPERCandidateCellList encodes a complete named list.
func MarshalAPERCandidateCellList(v CandidateCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCandidatePCIList encodes a complete named list.
func MarshalAPERCandidatePCIList(v CandidatePCIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellsToActivateList encodes a complete named list.
func MarshalAPERCellsToActivateList(v CellsToActivateListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERCandidateCellList decodes a complete named list.
func UnmarshalAPERCandidateCellList(data []byte, options ...aper.DecodeOption) (CandidateCellListComplete, aper.DecodeReport, error) {
	var v CandidateCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCandidatePCIList decodes a complete named list.
func UnmarshalAPERCandidatePCIList(data []byte, options ...aper.DecodeOption) (CandidatePCIListComplete, aper.DecodeReport, error) {
	var v CandidatePCIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellsToActivateList decodes a complete named list.
func UnmarshalAPERCellsToActivateList(data []byte, options ...aper.DecodeOption) (CellsToActivateListComplete, aper.DecodeReport, error) {
	var v CellsToActivateListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type X2TNLConfigurationInfoExtIEsValue struct {
	id                                      s00.ProtocolIEID
	received                                aper.WireSpan
	replay                                  aper.Snapshot
	opaque                                  aper.OpaqueOpenType
	isOpaque                                bool
	rowENBX2ExtendedTransportLayerAddresses *s18.ENBX2ExtTLAs
	rowENBIndirectX2TransportLayerAddresses *s00.ENBIndirectX2TransportLayerAddresses
}

func (v X2TNLConfigurationInfoExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(153):
		return v.rowENBX2ExtendedTransportLayerAddresses != nil
	case s00.ProtocolIEID(193):
		return v.rowENBIndirectX2TransportLayerAddresses != nil
	}
	return false
}

// Opaque returns the retained opaque open value of X2TNLConfigurationInfoExtIEsValue and reports whether the opaque alternative is selected.
func (v *X2TNLConfigurationInfoExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (X2TNLConfigurationInfoExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "X2TNLConfigurationInfo-ExtIEs"}}
}
func (X2TNLConfigurationInfoExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(153):
		return aper.UnknownSelector
	case s00.ProtocolIEID(193):
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

// AsENBX2ExtendedTransportLayerAddresses returns the selected ENBX2ExtendedTransportLayerAddresses value of X2TNLConfigurationInfoExtIEsValue and reports whether that alternative is active.
func (v *X2TNLConfigurationInfoExtIEsValue) AsENBX2ExtendedTransportLayerAddresses() (*s18.ENBX2ExtTLAs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(153) || v.rowENBX2ExtendedTransportLayerAddresses == nil {
		return nil, false
	}
	return v.rowENBX2ExtendedTransportLayerAddresses, true
}

// AsENBIndirectX2TransportLayerAddresses returns the selected ENBIndirectX2TransportLayerAddresses value of X2TNLConfigurationInfoExtIEsValue and reports whether that alternative is active.
func (v *X2TNLConfigurationInfoExtIEsValue) AsENBIndirectX2TransportLayerAddresses() (*s00.ENBIndirectX2TransportLayerAddresses, bool) {
	if v == nil || v.id != s00.ProtocolIEID(193) || v.rowENBIndirectX2TransportLayerAddresses == nil {
		return nil, false
	}
	return v.rowENBIndirectX2TransportLayerAddresses, true
}
func (v X2TNLConfigurationInfoExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (X2TNLConfigurationInfoExtIEsValue, error) {
	out := X2TNLConfigurationInfoExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(153):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERENBX2ExtTLAsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBX2ExtendedTransportLayerAddresses:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowENBX2ExtendedTransportLayerAddresses = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(193):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERENBIndirectX2TransportLayerAddressesFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBIndirectX2TransportLayerAddresses:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowENBIndirectX2TransportLayerAddresses = &value
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
func (v X2TNLConfigurationInfoExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v X2TNLConfigurationInfoExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(153):
		if v.rowENBX2ExtendedTransportLayerAddresses == nil {
			return nil, fmt.Errorf("%s missing value", "X2TNLConfigurationInfo-ExtIEs.id-eNBX2ExtendedTransportLayerAddresses:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ENBX2ExtTLAsComplete{Value: *v.rowENBX2ExtendedTransportLayerAddresses}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(193):
		if v.rowENBIndirectX2TransportLayerAddresses == nil {
			return nil, fmt.Errorf("%s missing value", "X2TNLConfigurationInfo-ExtIEs.id-eNBIndirectX2TransportLayerAddresses:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ENBIndirectX2TransportLayerAddressesComplete{Value: *v.rowENBIndirectX2TransportLayerAddresses}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "X2TNLConfigurationInfoExtIEsValue:", v.id)
	}
}

type UEContextResumeRequestIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABFailedToResumeListResumeReq *s18.ERABFailedToResumeListResumeReq
	rowRRCResumeCause                  *s00.RRCEstablishmentCause
}

func (v UEContextResumeRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(235):
		return v.rowERABFailedToResumeListResumeReq != nil
	case s00.ProtocolIEID(245):
		return v.rowRRCResumeCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextResumeRequestIEValue and reports whether the opaque alternative is selected.
func (v *UEContextResumeRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextResumeRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs"}}
}
func (UEContextResumeRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(235):
		return aper.UnknownSelector
	case s00.ProtocolIEID(245):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextResumeRequestIEValue and reports whether that alternative is active.
func (v *UEContextResumeRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextResumeRequestIEValue and reports whether that alternative is active.
func (v *UEContextResumeRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABFailedToResumeListResumeReq returns the selected ERABFailedToResumeListResumeReq value of UEContextResumeRequestIEValue and reports whether that alternative is active.
func (v *UEContextResumeRequestIEValue) AsERABFailedToResumeListResumeReq() (*s18.ERABFailedToResumeListResumeReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(235) || v.rowERABFailedToResumeListResumeReq == nil {
		return nil, false
	}
	return v.rowERABFailedToResumeListResumeReq, true
}

// AsRRCResumeCause returns the selected RRCResumeCause value of UEContextResumeRequestIEValue and reports whether that alternative is active.
func (v *UEContextResumeRequestIEValue) AsRRCResumeCause() (*s00.RRCEstablishmentCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(245) || v.rowRRCResumeCause == nil {
		return nil, false
	}
	return v.rowRRCResumeCause, true
}
func (v UEContextResumeRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextResumeRequestIEValue, error) {
	out := UEContextResumeRequestIEValue{id: id}
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
	case s00.ProtocolIEID(235):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABFailedToResumeListResumeReqFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToResumeListResumeReq:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToResumeListResumeReq = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(245):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 3, Path: "RRCEstablishmentCause"})
		value := s00.RRCEstablishmentCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RRCResumeCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRRCResumeCause = &value
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
func (v UEContextResumeRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextResumeRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeRequestIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeRequestIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(235):
		if v.rowERABFailedToResumeListResumeReq == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeRequestIEs.id-E-RABFailedToResumeListResumeReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABFailedToResumeListResumeReqComplete{Value: *v.rowERABFailedToResumeListResumeReq}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(245):
		if v.rowRRCResumeCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeRequestIEs.id-RRC-Resume-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRRCResumeCause), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextResumeRequestIEValue:", v.id)
	}
}

type UEContextResumeResponseIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowERABFailedToResumeListResumeRes *s18.ERABFailedToResumeListResumeRes
	rowCriticalityDiagnostics          *s26.CriticalityDiagnostics
	rowSecurityContext                 *s36.SecurityContext
	rowPendingDataIndication           *s00.PendingDataIndication
}

func (v UEContextResumeResponseIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(237):
		return v.rowERABFailedToResumeListResumeRes != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(40):
		return v.rowSecurityContext != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextResumeResponseIEValue and reports whether the opaque alternative is selected.
func (v *UEContextResumeResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextResumeResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeResponseIEs"}}
}
func (UEContextResumeResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(237):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(40):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABFailedToResumeListResumeRes returns the selected ERABFailedToResumeListResumeRes value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsERABFailedToResumeListResumeRes() (*s18.ERABFailedToResumeListResumeRes, bool) {
	if v == nil || v.id != s00.ProtocolIEID(237) || v.rowERABFailedToResumeListResumeRes == nil {
		return nil, false
	}
	return v.rowERABFailedToResumeListResumeRes, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsSecurityContext returns the selected SecurityContext value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsSecurityContext() (*s36.SecurityContext, bool) {
	if v == nil || v.id != s00.ProtocolIEID(40) || v.rowSecurityContext == nil {
		return nil, false
	}
	return v.rowSecurityContext, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of UEContextResumeResponseIEValue and reports whether that alternative is active.
func (v *UEContextResumeResponseIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}
func (v UEContextResumeResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextResumeResponseIEValue, error) {
	out := UEContextResumeResponseIEValue{id: id}
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
	case s00.ProtocolIEID(237):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERERABFailedToResumeListResumeResFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABFailedToResumeListResumeRes:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABFailedToResumeListResumeRes = &value
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
	case s00.ProtocolIEID(40):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s36.SecurityContext
		child := scope
		if err := s36.BridgeSecurityContextMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityContext:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityContext")
		if err != nil {
			return out, err
		}
		*s36.BridgeSecurityContextFieldPerPadding(&value) = padding
		*s36.BridgeSecurityContextFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeSecurityContextFieldReceivedBytes(&value))
		*s36.BridgeSecurityContextFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityContext = &value
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextResumeResponseIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextResumeResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(237):
		if v.rowERABFailedToResumeListResumeRes == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-E-RABFailedToResumeListResumeRes:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := ERABFailedToResumeListResumeResComplete{Value: *v.rowERABFailedToResumeListResumeRes}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(40):
		if v.rowSecurityContext == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-SecurityContext:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s36.BridgeSecurityContextMethodMarshalAPERBudget(v.rowSecurityContext, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextResumeResponseIEs.id-PendingDataIndication:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextResumeResponseIEValue:", v.id)
	}
}

type X2TNLConfigurationInfoExtIETable struct{}

func X2TNLConfigurationInfoExtIEs() X2TNLConfigurationInfoExtIETable {
	return X2TNLConfigurationInfoExtIETable{}
}

// ID returns the ASN.1 object-set identity of X2TNLConfigurationInfoExtIETable.
func (X2TNLConfigurationInfoExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "X2TNLConfigurationInfo-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by X2TNLConfigurationInfoExtIETable.
func (X2TNLConfigurationInfoExtIETable) Table() s00.X2TNLConfigurationInfoExtIEsValueExtensionTable {
	return func() s00.X2TNLConfigurationInfoExtIEsValueExtensionTable {
		sealed := s00.X2TNLConfigurationInfoExtIEsValueExtensionTable{}
		*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (X2TNLConfigurationInfoExtIETable) infoENBX2ExtendedTransportLayerAddresses() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: X2TNLConfigurationInfoExtIEs().ID(), ID: s00.ProtocolExtensionID(153), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENBX2ExtTLAs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "X2TNLConfigurationInfo-ExtIEs", Row: "id-eNBX2ExtendedTransportLayerAddresses"}}}
}

// ENBX2ExtendedTransportLayerAddresses returns the typed binding for the ENBX2ExtendedTransportLayerAddresses row of X2TNLConfigurationInfoExtIETable.
func (t X2TNLConfigurationInfoExtIETable) ENBX2ExtendedTransportLayerAddresses() X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding {
	return X2TNLConfigurationInfoExtIEsENBX2ExtTLAsExtBinding{info: t.infoENBX2ExtendedTransportLayerAddresses(), codec: func() s18.ENBX2ExtTLAsValueCodec {
		sealed := s18.ENBX2ExtTLAsValueCodec{}
		*s18.BridgeENBX2ExtTLAsValueCodecFieldPath(&sealed) = "ENBX2ExtTLAs"
		*s18.BridgeENBX2ExtTLAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ENBX2ExtTLAs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ENBX2ExtTLAs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBX2ExtTLAs")
			var zero X2TNLConfigurationInfoExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(153), raw)
			if err != nil {
				var empty s18.ENBX2ExtTLAs
				return empty, runtime.WrapDecodePath(err, "ENBX2ExtTLAs")
			}
			value, ok := decoded.AsENBX2ExtendedTransportLayerAddresses()
			if !ok {
				var empty s18.ENBX2ExtTLAs
				return empty, fmt.Errorf("binding X2TNLConfigurationInfo-ExtIEs.id-eNBX2ExtendedTransportLayerAddresses: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeENBX2ExtTLAsValueCodecFieldEncode(&sealed) = func(value s18.ENBX2ExtTLAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (X2TNLConfigurationInfoExtIEsValue{id: s00.ProtocolIEID(153), rowENBX2ExtendedTransportLayerAddresses: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeENBX2ExtTLAsValueCodecFieldCapture(&sealed) = func(v s18.ENBX2ExtTLAs, options aper.DecodeState) (s18.ENBX2ExtTLAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APENBX2ExtTLAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeENBX2ExtTLAsValueCodecFieldCompare(&sealed) = func(v s18.ENBX2ExtTLAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APENBX2ExtTLAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s18.BridgeENBX2ExtTLAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBX2ExtTLAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ENBX2ExtTLAs) X2TNLConfigurationInfoExtIEsValue {
			return X2TNLConfigurationInfoExtIEsValue{id: s00.ProtocolIEID(153), rowENBX2ExtendedTransportLayerAddresses: &value}
		}, get: func(value *X2TNLConfigurationInfoExtIEsValue) (*s18.ENBX2ExtTLAs, bool) {
			return value.AsENBX2ExtendedTransportLayerAddresses()
		}}
}
func (X2TNLConfigurationInfoExtIETable) infoENBIndirectX2TransportLayerAddresses() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: X2TNLConfigurationInfoExtIEs().ID(), ID: s00.ProtocolExtensionID(193), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENBIndirectX2TransportLayerAddresses"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "X2TNLConfigurationInfo-ExtIEs", Row: "id-eNBIndirectX2TransportLayerAddresses"}}}
}

// ENBIndirectX2TransportLayerAddresses returns the typed binding for the ENBIndirectX2TransportLayerAddresses row of X2TNLConfigurationInfoExtIETable.
func (t X2TNLConfigurationInfoExtIETable) ENBIndirectX2TransportLayerAddresses() X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding {
	return X2TNLConfigurationInfoExtIEsENBIndirectX2TransportLayerAddressesExtBinding{info: t.infoENBIndirectX2TransportLayerAddresses(), codec: func() s00.ENBIndirectX2TransportLayerAddressesValueCodec {
		sealed := s00.ENBIndirectX2TransportLayerAddressesValueCodec{}
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldPath(&sealed) = "ENBIndirectX2TransportLayerAddresses"
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBIndirectX2TransportLayerAddresses, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBIndirectX2TransportLayerAddresses
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBIndirectX2TransportLayerAddresses")
			var zero X2TNLConfigurationInfoExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(193), raw)
			if err != nil {
				var empty s00.ENBIndirectX2TransportLayerAddresses
				return empty, runtime.WrapDecodePath(err, "ENBIndirectX2TransportLayerAddresses")
			}
			value, ok := decoded.AsENBIndirectX2TransportLayerAddresses()
			if !ok {
				var empty s00.ENBIndirectX2TransportLayerAddresses
				return empty, fmt.Errorf("binding X2TNLConfigurationInfo-ExtIEs.id-eNBIndirectX2TransportLayerAddresses: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldEncode(&sealed) = func(value s00.ENBIndirectX2TransportLayerAddresses, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (X2TNLConfigurationInfoExtIEsValue{id: s00.ProtocolIEID(193), rowENBIndirectX2TransportLayerAddresses: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldCapture(&sealed) = func(v s00.ENBIndirectX2TransportLayerAddresses, options aper.DecodeState) (s00.ENBIndirectX2TransportLayerAddresses, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APENBIndirectX2TransportLayerAddresses(&v,
				&s,
			)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldCompare(&sealed) = func(v s00.ENBIndirectX2TransportLayerAddresses, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APENBIndirectX2TransportLayerAddresses(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeENBIndirectX2TransportLayerAddressesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBIndirectX2TransportLayerAddresses"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ENBIndirectX2TransportLayerAddresses) X2TNLConfigurationInfoExtIEsValue {
			return X2TNLConfigurationInfoExtIEsValue{id: s00.ProtocolIEID(193), rowENBIndirectX2TransportLayerAddresses: &value}
		}, get: func(value *X2TNLConfigurationInfoExtIEsValue) (*s00.ENBIndirectX2TransportLayerAddresses, bool) {
			return value.AsENBIndirectX2TransportLayerAddresses()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in X2TNLConfigurationInfoExtIETable.
func (t X2TNLConfigurationInfoExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (X2TNLConfigurationInfoExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(153):
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-eNBX2ExtendedTransportLayerAddresses requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(193):
		return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-eNBIndirectX2TransportLayerAddresses requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return X2TNLConfigurationInfoExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return X2TNLConfigurationInfoExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: X2TNLConfigurationInfoExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextResumeRequestIETable struct{}

func UEContextResumeRequestIEs() UEContextResumeRequestIETable {
	return UEContextResumeRequestIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextResumeRequestIETable.
func (UEContextResumeRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextResumeRequestIETable.
func (UEContextResumeRequestIETable) Table() s00.UEContextResumeRequestIEValueIETable {
	return func() s00.UEContextResumeRequestIEValueIETable {
		sealed := s00.UEContextResumeRequestIEValueIETable{}
		*s00.BridgeUEContextResumeRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextResumeRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextResumeRequestIETable.
func (t UEContextResumeRequestIETable) MMEUES1APID() UEContextResumeRequestMMEUES1APIDIEBinding {
	return UEContextResumeRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextResumeRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextResumeRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextResumeRequestIEValue {
			return UEContextResumeRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextResumeRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextResumeRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextResumeRequestIETable.
func (t UEContextResumeRequestIETable) ENBUES1APID() UEContextResumeRequestENBUES1APIDIEBinding {
	return UEContextResumeRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextResumeRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextResumeRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextResumeRequestIEValue {
			return UEContextResumeRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextResumeRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UEContextResumeRequestIETable) infoERABFailedToResumeListResumeReq() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeRequestIEs().ID(), ID: s00.ProtocolIEID(235), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABFailedToResumeListResumeReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs", Row: "id-E-RABFailedToResumeListResumeReq"}}}
}

// ERABFailedToResumeListResumeReq returns the typed binding for the ERABFailedToResumeListResumeReq row of UEContextResumeRequestIETable.
func (t UEContextResumeRequestIETable) ERABFailedToResumeListResumeReq() UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding {
	return UEContextResumeRequestERABFailedToResumeListResumeReqIEBinding{info: t.infoERABFailedToResumeListResumeReq(), codec: func() s18.ERABFailedToResumeListResumeReqValueCodec {
		sealed := s18.ERABFailedToResumeListResumeReqValueCodec{}
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldPath(&sealed) = "ERABFailedToResumeListResumeReq"
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ERABFailedToResumeListResumeReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ERABFailedToResumeListResumeReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABFailedToResumeListResumeReq")
			var zero UEContextResumeRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(235), raw)
			if err != nil {
				var empty s18.ERABFailedToResumeListResumeReq
				return empty, runtime.WrapDecodePath(err, "ERABFailedToResumeListResumeReq")
			}
			value, ok := decoded.AsERABFailedToResumeListResumeReq()
			if !ok {
				var empty s18.ERABFailedToResumeListResumeReq
				return empty, fmt.Errorf("binding UEContextResumeRequestIEs.id-E-RABFailedToResumeListResumeReq: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldEncode(&sealed) = func(value s18.ERABFailedToResumeListResumeReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeRequestIEValue{id: s00.ProtocolIEID(235), rowERABFailedToResumeListResumeReq: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldCapture(&sealed) = func(v s18.ERABFailedToResumeListResumeReq, options aper.DecodeState) (s18.ERABFailedToResumeListResumeReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APERABFailedToResumeListResumeReq(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldCompare(&sealed) = func(v s18.ERABFailedToResumeListResumeReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APERABFailedToResumeListResumeReq(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeERABFailedToResumeListResumeReqValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABFailedToResumeListResumeReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ERABFailedToResumeListResumeReq) UEContextResumeRequestIEValue {
			return UEContextResumeRequestIEValue{id: s00.ProtocolIEID(235), rowERABFailedToResumeListResumeReq: &value}
		}, get: func(value *UEContextResumeRequestIEValue) (*s18.ERABFailedToResumeListResumeReq, bool) {
			return value.AsERABFailedToResumeListResumeReq()
		}}
}
func (UEContextResumeRequestIETable) infoRRCResumeCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextResumeRequestIEs().ID(), ID: s00.ProtocolIEID(245), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RRC-Establishment-Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextResumeRequestIEs", Row: "id-RRC-Resume-Cause"}}}
}

// RRCResumeCause returns the typed binding for the RRCResumeCause row of UEContextResumeRequestIETable.
func (t UEContextResumeRequestIETable) RRCResumeCause() UEContextResumeRequestRRCEstablishmentCauseIEBinding {
	return UEContextResumeRequestRRCEstablishmentCauseIEBinding{info: t.infoRRCResumeCause(), codec: func() s01.RRCEstablishmentCauseValueCodec {
		sealed := s01.RRCEstablishmentCauseValueCodec{}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldPath(&sealed) = "RRCEstablishmentCause"
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RRCEstablishmentCause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RRCEstablishmentCause")
			var zero UEContextResumeRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(245), raw)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, runtime.WrapDecodePath(err, "RRCEstablishmentCause")
			}
			value, ok := decoded.AsRRCResumeCause()
			if !ok {
				var empty s00.RRCEstablishmentCause
				return empty, fmt.Errorf("binding UEContextResumeRequestIEs.id-RRC-Resume-Cause: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&sealed) = func(value s00.RRCEstablishmentCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextResumeRequestIEValue{id: s00.ProtocolIEID(245), rowRRCResumeCause: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCapture(&sealed) = func(v s00.RRCEstablishmentCause, options aper.DecodeState) (s00.RRCEstablishmentCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRRCEstablishmentCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCompare(&sealed) = func(v s00.RRCEstablishmentCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APRRCEstablishmentCause(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RRCEstablishmentCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RRCEstablishmentCause) UEContextResumeRequestIEValue {
			return UEContextResumeRequestIEValue{id: s00.ProtocolIEID(245), rowRRCResumeCause: &value}
		}, get: func(value *UEContextResumeRequestIEValue) (*s00.RRCEstablishmentCause, bool) {
			return value.AsRRCResumeCause()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextResumeRequestIETable.
func (t UEContextResumeRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextResumeRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(235):
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABFailedToResumeListResumeReq requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(245):
		return UEContextResumeRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RRC-Resume-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextResumeRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextResumeRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextResumeRequestIEField{Id: id, Criticality: criticality, Value: UEContextResumeRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// BearersSubjectToEarlyStatusTransferListCodec binds the complete source value type.
func BearersSubjectToEarlyStatusTransferListCodec() s17.BearersSubjectToEarlyStatusTransferListValueCodec {
	return func() s17.BearersSubjectToEarlyStatusTransferListValueCodec {
		sealed := s17.BearersSubjectToEarlyStatusTransferListValueCodec{}
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferList"
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferList, error) {
			var complete BearersSubjectToEarlyStatusTransferListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.BearersSubjectToEarlyStatusTransferList
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToEarlyStatusTransferList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BearersSubjectToEarlyStatusTransferListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferList, options aper.DecodeState) (s17.BearersSubjectToEarlyStatusTransferList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToEarlyStatusTransferList, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s17.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToEarlyStatusTransferList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferListCodec binds the complete source value type.
func BearersSubjectToStatusTransferListCodec() s25.BearersSubjectToStatusTransferListValueCodec {
	return func() s25.BearersSubjectToStatusTransferListValueCodec {
		sealed := s25.BearersSubjectToStatusTransferListValueCodec{}
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldPath(&sealed) = "BearersSubjectToStatusTransferList"
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s25.BearersSubjectToStatusTransferList, error) {
			var complete BearersSubjectToStatusTransferListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s25.BearersSubjectToStatusTransferList
				return zero, err
			}
			return complete.Value, nil
		}
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldEncode(&sealed) = func(value s25.BearersSubjectToStatusTransferList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BearersSubjectToStatusTransferListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldCapture(&sealed) = func(v s25.BearersSubjectToStatusTransferList, options aper.DecodeState) (s25.BearersSubjectToStatusTransferList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APBearersSubjectToStatusTransferList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldCompare(&sealed) = func(v s25.BearersSubjectToStatusTransferList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APBearersSubjectToStatusTransferList(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s25.BridgeBearersSubjectToStatusTransferListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToStatusTransferList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BluetoothMeasConfigNameListCodec binds the complete source value type.
func BluetoothMeasConfigNameListCodec() s00.BluetoothMeasConfigNameListValueCodec {
	return func() s00.BluetoothMeasConfigNameListValueCodec {
		sealed := s00.BluetoothMeasConfigNameListValueCodec{}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldPath(&sealed) = "BluetoothMeasConfigNameList"
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BluetoothMeasConfigNameList, error) {
			var complete BluetoothMeasConfigNameListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.BluetoothMeasConfigNameList
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldEncode(&sealed) = func(value s00.BluetoothMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BluetoothMeasConfigNameListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldCapture(&sealed) = func(v s00.BluetoothMeasConfigNameList, options aper.DecodeState) (s00.BluetoothMeasConfigNameList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldCompare(&sealed) = func(v s00.BluetoothMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothMeasConfigNameList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinEAICodec binds the complete source value type.
func CancelledCellinEAICodec() s20.CancelledCellinEAIValueCodec {
	return func() s20.CancelledCellinEAIValueCodec {
		sealed := s20.CancelledCellinEAIValueCodec{}
		*s20.BridgeCancelledCellinEAIValueCodecFieldPath(&sealed) = "CancelledCellinEAI"
		*s20.BridgeCancelledCellinEAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CancelledCellinEAI, error) {
			var complete CancelledCellinEAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CancelledCellinEAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCancelledCellinEAIValueCodecFieldEncode(&sealed) = func(value s20.CancelledCellinEAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CancelledCellinEAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCancelledCellinEAIValueCodecFieldCapture(&sealed) = func(v s20.CancelledCellinEAI, options aper.DecodeState) (s20.CancelledCellinEAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCancelledCellinEAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s20.BridgeCancelledCellinEAIValueCodecFieldCompare(&sealed) = func(v s20.CancelledCellinEAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCancelledCellinEAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCancelledCellinEAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinEAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinTAICodec binds the complete source value type.
func CancelledCellinTAICodec() s20.CancelledCellinTAIValueCodec {
	return func() s20.CancelledCellinTAIValueCodec {
		sealed := s20.CancelledCellinTAIValueCodec{}
		*s20.BridgeCancelledCellinTAIValueCodecFieldPath(&sealed) = "CancelledCellinTAI"
		*s20.BridgeCancelledCellinTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CancelledCellinTAI, error) {
			var complete CancelledCellinTAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CancelledCellinTAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCancelledCellinTAIValueCodecFieldEncode(&sealed) = func(value s20.CancelledCellinTAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CancelledCellinTAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCancelledCellinTAIValueCodecFieldCapture(&sealed) = func(v s20.CancelledCellinTAI, options aper.DecodeState) (s20.CancelledCellinTAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCancelledCellinTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s20.BridgeCancelledCellinTAIValueCodecFieldCompare(&sealed) = func(v s20.CancelledCellinTAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCancelledCellinTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCancelledCellinTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinTAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CandidateCellListCodec binds the complete source value type.
func CandidateCellListCodec() s21.CandidateCellListValueCodec {
	return func() s21.CandidateCellListValueCodec {
		sealed := s21.CandidateCellListValueCodec{}
		*s21.BridgeCandidateCellListValueCodecFieldPath(&sealed) = "CandidateCellList"
		*s21.BridgeCandidateCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.CandidateCellList, error) {
			var complete CandidateCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s21.CandidateCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s21.BridgeCandidateCellListValueCodecFieldEncode(&sealed) = func(value s21.CandidateCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CandidateCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s21.BridgeCandidateCellListValueCodecFieldCapture(&sealed) = func(v s21.CandidateCellList, options aper.DecodeState) (s21.CandidateCellList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCandidateCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s21.BridgeCandidateCellListValueCodecFieldCompare(&sealed) = func(v s21.CandidateCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCandidateCellList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s21.BridgeCandidateCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidateCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CandidatePCIListCodec binds the complete source value type.
func CandidatePCIListCodec() s17.CandidatePCIListValueCodec {
	return func() s17.CandidatePCIListValueCodec {
		sealed := s17.CandidatePCIListValueCodec{}
		*s17.BridgeCandidatePCIListValueCodecFieldPath(&sealed) = "CandidatePCIList"
		*s17.BridgeCandidatePCIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CandidatePCIList, error) {
			var complete CandidatePCIListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CandidatePCIList
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCandidatePCIListValueCodecFieldEncode(&sealed) = func(value s17.CandidatePCIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CandidatePCIListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCandidatePCIListValueCodecFieldCapture(&sealed) = func(v s17.CandidatePCIList, options aper.DecodeState) (s17.CandidatePCIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s25.BridgeCaptureS1APCandidatePCIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCandidatePCIListValueCodecFieldCompare(&sealed) = func(v s17.CandidatePCIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCandidatePCIList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeCandidatePCIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidatePCIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDBroadcastCodec binds the complete source value type.
func CellIDBroadcastCodec() s20.CellIDBroadcastValueCodec {
	return func() s20.CellIDBroadcastValueCodec {
		sealed := s20.CellIDBroadcastValueCodec{}
		*s20.BridgeCellIDBroadcastValueCodecFieldPath(&sealed) = "CellIDBroadcast"
		*s20.BridgeCellIDBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIDBroadcast, error) {
			var complete CellIDBroadcastComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CellIDBroadcast
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCellIDBroadcastValueCodecFieldEncode(&sealed) = func(value s20.CellIDBroadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIDBroadcastComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCellIDBroadcastValueCodecFieldCapture(&sealed) = func(v s20.CellIDBroadcast, options aper.DecodeState) (s20.CellIDBroadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCellIDBroadcast(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellIDBroadcastValueCodecFieldCompare(&sealed) = func(v s20.CellIDBroadcast, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCellIDBroadcast(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeCellIDBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDBroadcast"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDCancelledCodec binds the complete source value type.
func CellIDCancelledCodec() s20.CellIDCancelledValueCodec {
	return func() s20.CellIDCancelledValueCodec {
		sealed := s20.CellIDCancelledValueCodec{}
		*s20.BridgeCellIDCancelledValueCodecFieldPath(&sealed) = "CellIDCancelled"
		*s20.BridgeCellIDCancelledValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIDCancelled, error) {
			var complete CellIDCancelledComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CellIDCancelled
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCellIDCancelledValueCodecFieldEncode(&sealed) = func(value s20.CellIDCancelled, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIDCancelledComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCellIDCancelledValueCodecFieldCapture(&sealed) = func(v s20.CellIDCancelled, options aper.DecodeState) (s20.CellIDCancelled, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCellIDCancelled(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellIDCancelledValueCodecFieldCompare(&sealed) = func(v s20.CellIDCancelled, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCellIDCancelled(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeCellIDCancelledValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDCancelled"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIdListforMDTCodec binds the complete source value type.
func CellIdListforMDTCodec() s20.CellIdListforMDTValueCodec {
	return func() s20.CellIdListforMDTValueCodec {
		sealed := s20.CellIdListforMDTValueCodec{}
		*s20.BridgeCellIdListforMDTValueCodecFieldPath(&sealed) = "CellIdListforMDT"
		*s20.BridgeCellIdListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIdListforMDT, error) {
			var complete CellIdListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CellIdListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCellIdListforMDTValueCodecFieldEncode(&sealed) = func(value s20.CellIdListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIdListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCellIdListforMDTValueCodecFieldCapture(&sealed) = func(v s20.CellIdListforMDT, options aper.DecodeState) (s20.CellIdListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s25.BridgeCaptureS1APCellIdListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellIdListforMDTValueCodecFieldCompare(&sealed) = func(v s20.CellIdListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCellIdListforMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeCellIdListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIdListforQMCCodec binds the complete source value type.
func CellIdListforQMCCodec() s20.CellIdListforQMCValueCodec {
	return func() s20.CellIdListforQMCValueCodec {
		sealed := s20.CellIdListforQMCValueCodec{}
		*s20.BridgeCellIdListforQMCValueCodecFieldPath(&sealed) = "CellIdListforQMC"
		*s20.BridgeCellIdListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CellIdListforQMC, error) {
			var complete CellIdListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CellIdListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCellIdListforQMCValueCodecFieldEncode(&sealed) = func(value s20.CellIdListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIdListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCellIdListforQMCValueCodecFieldCapture(&sealed) = func(v s20.CellIdListforQMC, options aper.DecodeState) (s20.CellIdListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s25.BridgeCaptureS1APCellIdListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeCellIdListforQMCValueCodecFieldCompare(&sealed) = func(v s20.CellIdListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCellIdListforQMC(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeCellIdListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellsToActivateListCodec binds the complete source value type.
func CellsToActivateListCodec() s17.CellsToActivateListValueCodec {
	return func() s17.CellsToActivateListValueCodec {
		sealed := s17.CellsToActivateListValueCodec{}
		*s17.BridgeCellsToActivateListValueCodecFieldPath(&sealed) = "CellsToActivateList"
		*s17.BridgeCellsToActivateListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellsToActivateList, error) {
			var complete CellsToActivateListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CellsToActivateList
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCellsToActivateListValueCodecFieldEncode(&sealed) = func(value s17.CellsToActivateList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellsToActivateListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCellsToActivateListValueCodecFieldCapture(&sealed) = func(v s17.CellsToActivateList, options aper.DecodeState) (s17.CellsToActivateList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCellsToActivateList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellsToActivateListValueCodecFieldCompare(&sealed) = func(v s17.CellsToActivateList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCellsToActivateList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCellsToActivateListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellsToActivateList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinEAICodec binds the complete source value type.
func CompletedCellinEAICodec() s20.CompletedCellinEAIValueCodec {
	return func() s20.CompletedCellinEAIValueCodec {
		sealed := s20.CompletedCellinEAIValueCodec{}
		*s20.BridgeCompletedCellinEAIValueCodecFieldPath(&sealed) = "CompletedCellinEAI"
		*s20.BridgeCompletedCellinEAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CompletedCellinEAI, error) {
			var complete CompletedCellinEAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CompletedCellinEAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCompletedCellinEAIValueCodecFieldEncode(&sealed) = func(value s20.CompletedCellinEAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CompletedCellinEAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCompletedCellinEAIValueCodecFieldCapture(&sealed) = func(v s20.CompletedCellinEAI, options aper.DecodeState) (s20.CompletedCellinEAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCompletedCellinEAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s20.BridgeCompletedCellinEAIValueCodecFieldCompare(&sealed) = func(v s20.CompletedCellinEAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCompletedCellinEAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCompletedCellinEAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CompletedCellinEAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CompletedCellinTAICodec binds the complete source value type.
func CompletedCellinTAICodec() s20.CompletedCellinTAIValueCodec {
	return func() s20.CompletedCellinTAIValueCodec {
		sealed := s20.CompletedCellinTAIValueCodec{}
		*s20.BridgeCompletedCellinTAIValueCodecFieldPath(&sealed) = "CompletedCellinTAI"
		*s20.BridgeCompletedCellinTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.CompletedCellinTAI, error) {
			var complete CompletedCellinTAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.CompletedCellinTAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeCompletedCellinTAIValueCodecFieldEncode(&sealed) = func(value s20.CompletedCellinTAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CompletedCellinTAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeCompletedCellinTAIValueCodecFieldCapture(&sealed) = func(v s20.CompletedCellinTAI, options aper.DecodeState) (s20.CompletedCellinTAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCompletedCellinTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s20.BridgeCompletedCellinTAIValueCodecFieldCompare(&sealed) = func(v s20.CompletedCellinTAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCompletedCellinTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeCompletedCellinTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CompletedCellinTAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CriticalityDiagnosticsIEListCodec binds the complete source value type.
func CriticalityDiagnosticsIEListCodec() s17.CriticalityDiagnosticsIEListValueCodec {
	return func() s17.CriticalityDiagnosticsIEListValueCodec {
		sealed := s17.CriticalityDiagnosticsIEListValueCodec{}
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsIEList"
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CriticalityDiagnosticsIEList, error) {
			var complete CriticalityDiagnosticsIEListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CriticalityDiagnosticsIEList
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(&sealed) = func(value s17.CriticalityDiagnosticsIEList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CriticalityDiagnosticsIEListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(&sealed) = func(v s17.CriticalityDiagnosticsIEList, options aper.DecodeState) (s17.CriticalityDiagnosticsIEList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APCriticalityDiagnosticsIEList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(&sealed) = func(v s17.CriticalityDiagnosticsIEList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s26.BridgeCompareS1APCriticalityDiagnosticsIEList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ECGIListCodec binds the complete source value type.
func ECGIListCodec() s20.ECGIListValueCodec {
	return func() s20.ECGIListValueCodec {
		sealed := s20.ECGIListValueCodec{}
		*s20.BridgeECGIListValueCodecFieldPath(&sealed) = "ECGIList"
		*s20.BridgeECGIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ECGIList, error) {
			var complete ECGIListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.ECGIList
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeECGIListValueCodecFieldEncode(&sealed) = func(value s20.ECGIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ECGIListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeECGIListValueCodecFieldCapture(&sealed) = func(v s20.ECGIList, options aper.DecodeState) (s20.ECGIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s25.BridgeCaptureS1APECGIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeECGIListValueCodecFieldCompare(&sealed) = func(v s20.ECGIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APECGIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeECGIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECGIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBIndirectX2TransportLayerAddressesCodec binds the complete APER value type.
func ENBIndirectX2TransportLayerAddressesCodec() s00.ENBIndirectX2TransportLayerAddressesValueCodec {
	return X2TNLConfigurationInfoExtIEs().ENBIndirectX2TransportLayerAddresses().Codec()
}

// ENBX2ExtTLAsCodec binds the complete APER value type.
func ENBX2ExtTLAsCodec() s18.ENBX2ExtTLAsValueCodec {
	return X2TNLConfigurationInfoExtIEs().ENBX2ExtendedTransportLayerAddresses().Codec()
}

// ENBX2GTPTLAsCodec binds the complete source value type.
func ENBX2GTPTLAsCodec() s00.ENBX2GTPTLAsValueCodec {
	return func() s00.ENBX2GTPTLAsValueCodec {
		sealed := s00.ENBX2GTPTLAsValueCodec{}
		*s00.BridgeENBX2GTPTLAsValueCodecFieldPath(&sealed) = "ENBX2GTPTLAs"
		*s00.BridgeENBX2GTPTLAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBX2GTPTLAs, error) {
			var complete ENBX2GTPTLAsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ENBX2GTPTLAs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeENBX2GTPTLAsValueCodecFieldEncode(&sealed) = func(value s00.ENBX2GTPTLAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ENBX2GTPTLAsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeENBX2GTPTLAsValueCodecFieldCapture(&sealed) = func(v s00.ENBX2GTPTLAs, options aper.DecodeState) (s00.ENBX2GTPTLAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APENBX2GTPTLAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBX2GTPTLAsValueCodecFieldCompare(&sealed) = func(v s00.ENBX2GTPTLAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APENBX2GTPTLAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeENBX2GTPTLAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBX2GTPTLAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBX2TLAsCodec binds the complete source value type.
func ENBX2TLAsCodec() s00.ENBX2TLAsValueCodec {
	return func() s00.ENBX2TLAsValueCodec {
		sealed := s00.ENBX2TLAsValueCodec{}
		*s00.BridgeENBX2TLAsValueCodecFieldPath(&sealed) = "ENBX2TLAs"
		*s00.BridgeENBX2TLAsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBX2TLAs, error) {
			var complete ENBX2TLAsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.ENBX2TLAs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeENBX2TLAsValueCodecFieldEncode(&sealed) = func(value s00.ENBX2TLAs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ENBX2TLAsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeENBX2TLAsValueCodecFieldCapture(&sealed) = func(v s00.ENBX2TLAs, options aper.DecodeState) (s00.ENBX2TLAs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APENBX2TLAs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBX2TLAsValueCodecFieldCompare(&sealed) = func(v s00.ENBX2TLAs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APENBX2TLAs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeENBX2TLAsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBX2TLAs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EPLMNsCodec binds the complete source value type.
func EPLMNsCodec() s00.EPLMNsValueCodec {
	return func() s00.EPLMNsValueCodec {
		sealed := s00.EPLMNsValueCodec{}
		*s00.BridgeEPLMNsValueCodecFieldPath(&sealed) = "EPLMNs"
		*s00.BridgeEPLMNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EPLMNs, error) {
			var complete EPLMNsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.EPLMNs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeEPLMNsValueCodecFieldEncode(&sealed) = func(value s00.EPLMNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := EPLMNsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeEPLMNsValueCodecFieldCapture(&sealed) = func(v s00.EPLMNs, options aper.DecodeState) (s00.EPLMNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APEPLMNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEPLMNsValueCodecFieldCompare(&sealed) = func(v s00.EPLMNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APEPLMNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEPLMNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EPLMNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABFailedToResumeListResumeReqCodec binds the complete APER value type.
func ERABFailedToResumeListResumeReqCodec() s18.ERABFailedToResumeListResumeReqValueCodec {
	return UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Codec()
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERBudget(v *CNTypeRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCSGIdListCompleteMethodMarshalAPERBudget(v *CSGIdListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeConnectedengNBListCompleteMethodMarshalAPERBudget(v *ConnectedengNBListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDAPSResponseInfoListCompleteMethodMarshalAPERBudget(v *DAPSResponseInfoListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECGIListForRestartCompleteMethodMarshalAPERBudget(v *ECGIListForRestartComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABAdmittedListCompleteMethodMarshalAPERBudget(v *ERABAdmittedListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeERABFailedToResumeListResumeResCompleteMethodMarshalAPERLegacy(v *ERABFailedToResumeListResumeResComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeERABFailedToResumeListResumeResCompleteMethodUnmarshalAPERLegacy(v *ERABFailedToResumeListResumeResComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEEarlyStatusTransferFieldPerPadding(v *MMEEarlyStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEEarlyStatusTransferFieldReceived(v *MMEEarlyStatusTransfer) *bool { return &v.received }
func BridgeMMEEarlyStatusTransferFieldReceivedAbsolute(v *MMEEarlyStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEEarlyStatusTransferFieldReceivedBytes(v *MMEEarlyStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEEarlyStatusTransferFieldReceivedLocation(v *MMEEarlyStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v *MMEEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEEarlyStatusTransferMethodUnmarshalAPERFrom(v *MMEEarlyStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEEarlyStatusTransferMethodUnmarshalAPERWithOptions(v *MMEEarlyStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEEarlyStatusTransferValueCodecFieldCapture(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, aper.DecodeState) (MMEEarlyStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferValueCodecFieldCompare(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferValueCodecFieldContext(v *MMEEarlyStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferValueCodecFieldDecode(v *MMEEarlyStatusTransferValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransfer, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferValueCodecFieldEncode(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferValueCodecFieldPath(v *MMEEarlyStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeRequestFieldPerPadding(v *UEContextResumeRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextResumeRequestFieldReceived(v *UEContextResumeRequest) *bool { return &v.received }
func BridgeUEContextResumeRequestFieldReceivedAbsolute(v *UEContextResumeRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextResumeRequestFieldReceivedBytes(v *UEContextResumeRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextResumeRequestFieldReceivedLocation(v *UEContextResumeRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextResumeRequestIEFieldMethodMarshalAPERTo(v *UEContextResumeRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextResumeRequestIEValueFieldId(v *UEContextResumeRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextResumeRequestIEValueFieldIsOpaque(v *UEContextResumeRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextResumeRequestIEValueFieldOpaque(v *UEContextResumeRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextResumeRequestIEValueFieldRowENBUES1APID(v *UEContextResumeRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextResumeRequestIEValueFieldRowERABFailedToResumeListResumeReq(v *UEContextResumeRequestIEValue) **s18.ERABFailedToResumeListResumeReq {
	return &v.rowERABFailedToResumeListResumeReq
}
func BridgeUEContextResumeRequestIEValueFieldRowMMEUES1APID(v *UEContextResumeRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextResumeRequestIEValueFieldRowRRCResumeCause(v *UEContextResumeRequestIEValue) **s00.RRCEstablishmentCause {
	return &v.rowRRCResumeCause
}
func BridgeUEContextResumeRequestIEValueMethodMatchesID(v UEContextResumeRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextResumeRequestMethodMarshalAPERBudget(v *UEContextResumeRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextResumeRequestMethodUnmarshalAPERFrom(v *UEContextResumeRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextResumeRequestMethodUnmarshalAPERWithOptions(v *UEContextResumeRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextResumeRequestValueCodecFieldCapture(v *UEContextResumeRequestValueCodec) *func(UEContextResumeRequest, aper.DecodeState) (UEContextResumeRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeRequestValueCodecFieldCompare(v *UEContextResumeRequestValueCodec) *func(UEContextResumeRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeRequestValueCodecFieldContext(v *UEContextResumeRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeRequestValueCodecFieldDecode(v *UEContextResumeRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeRequest, error) {
	return &v.decode
}
func BridgeUEContextResumeRequestValueCodecFieldEncode(v *UEContextResumeRequestValueCodec) *func(UEContextResumeRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeRequestValueCodecFieldPath(v *UEContextResumeRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseCriticalityDiagnosticsIEBindingFieldCodec(v *UEContextResumeResponseCriticalityDiagnosticsIEBinding) *s26.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeUEContextResumeResponseCriticalityDiagnosticsIEBindingFieldGet(v *UEContextResumeResponseCriticalityDiagnosticsIEBinding) *func(*UEContextResumeResponseIEValue) (*s26.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeUEContextResumeResponseCriticalityDiagnosticsIEBindingFieldInfo(v *UEContextResumeResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeResponseCriticalityDiagnosticsIEBindingFieldInject(v *UEContextResumeResponseCriticalityDiagnosticsIEBinding) *func(s26.CriticalityDiagnostics) UEContextResumeResponseIEValue {
	return &v.inject
}
func BridgeUEContextResumeResponseENBUES1APIDIEBindingFieldCodec(v *UEContextResumeResponseENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextResumeResponseENBUES1APIDIEBindingFieldGet(v *UEContextResumeResponseENBUES1APIDIEBinding) *func(*UEContextResumeResponseIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextResumeResponseENBUES1APIDIEBindingFieldInfo(v *UEContextResumeResponseENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeResponseENBUES1APIDIEBindingFieldInject(v *UEContextResumeResponseENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextResumeResponseIEValue {
	return &v.inject
}
func BridgeUEContextResumeResponseERABFailedToResumeListResumeResIEBindingFieldCodec(v *UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) *s18.ERABFailedToResumeListResumeResValueCodec {
	return &v.codec
}
func BridgeUEContextResumeResponseERABFailedToResumeListResumeResIEBindingFieldGet(v *UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) *func(*UEContextResumeResponseIEValue) (*s18.ERABFailedToResumeListResumeRes, bool) {
	return &v.get
}
func BridgeUEContextResumeResponseERABFailedToResumeListResumeResIEBindingFieldInfo(v *UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeResponseERABFailedToResumeListResumeResIEBindingFieldInject(v *UEContextResumeResponseERABFailedToResumeListResumeResIEBinding) *func(s18.ERABFailedToResumeListResumeRes) UEContextResumeResponseIEValue {
	return &v.inject
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldCapture(v *UEContextResumeResponseIEContainerValueCodec) *func(UEContextResumeResponseIEContainer, aper.DecodeState) (UEContextResumeResponseIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldCompare(v *UEContextResumeResponseIEContainerValueCodec) *func(UEContextResumeResponseIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldContext(v *UEContextResumeResponseIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldDecode(v *UEContextResumeResponseIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeResponseIEContainer, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldEncode(v *UEContextResumeResponseIEContainerValueCodec) *func(UEContextResumeResponseIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseIEContainerValueCodecFieldPath(v *UEContextResumeResponseIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseIEFieldFieldReplay(v *UEContextResumeResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeResponseIEFieldFieldWithoutReplay(v *UEContextResumeResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeResponseIEFieldMethodMarshalAPERTo(v *UEContextResumeResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextResumeResponseIEFieldMethodUnmarshalAPERFrom(v *UEContextResumeResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldCapture(v *UEContextResumeResponseIEFieldValueCodec) *func(UEContextResumeResponseIEField, aper.DecodeState) (UEContextResumeResponseIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldCompare(v *UEContextResumeResponseIEFieldValueCodec) *func(UEContextResumeResponseIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldContext(v *UEContextResumeResponseIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldDecode(v *UEContextResumeResponseIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeResponseIEField, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldEncode(v *UEContextResumeResponseIEFieldValueCodec) *func(UEContextResumeResponseIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseIEFieldValueCodecFieldPath(v *UEContextResumeResponseIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *func(UEContextResumeResponseIEValueERABIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *func(UEContextResumeResponseIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldContext(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *func(UEContextResumeResponseIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseIEValueERABIEContainerListValueCodecFieldPath(v *UEContextResumeResponseIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseIEValueFieldId(v *UEContextResumeResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextResumeResponseIEValueFieldIsOpaque(v *UEContextResumeResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextResumeResponseIEValueFieldOpaque(v *UEContextResumeResponseIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextResumeResponseIEValueFieldRowCriticalityDiagnostics(v *UEContextResumeResponseIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeUEContextResumeResponseIEValueFieldRowENBUES1APID(v *UEContextResumeResponseIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextResumeResponseIEValueFieldRowERABFailedToResumeListResumeRes(v *UEContextResumeResponseIEValue) **s18.ERABFailedToResumeListResumeRes {
	return &v.rowERABFailedToResumeListResumeRes
}
func BridgeUEContextResumeResponseIEValueFieldRowMMEUES1APID(v *UEContextResumeResponseIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextResumeResponseIEValueFieldRowPendingDataIndication(v *UEContextResumeResponseIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeUEContextResumeResponseIEValueFieldRowSecurityContext(v *UEContextResumeResponseIEValue) **s36.SecurityContext {
	return &v.rowSecurityContext
}
func BridgeUEContextResumeResponseIEValueMethodCaptureSemantics(v UEContextResumeResponseIEValue, a0 aper.SemanticCapture) UEContextResumeResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextResumeResponseIEValueMethodCompareSemantics(v UEContextResumeResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextResumeResponseIEValueMethodDecode(v UEContextResumeResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextResumeResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextResumeResponseIEValueMethodEncodeFresh(v UEContextResumeResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextResumeResponseIEValueMethodMatchesID(v UEContextResumeResponseIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextResumeResponseIEValueMethodRule(v UEContextResumeResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextResumeResponseIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolIEContainerList, aper.DecodeState) (UEContextResumeResponseIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeResponseIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *func(UEContextResumeResponseIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextResumeResponseIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeResponseMMEUES1APIDIEBindingFieldCodec(v *UEContextResumeResponseMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextResumeResponseMMEUES1APIDIEBindingFieldGet(v *UEContextResumeResponseMMEUES1APIDIEBinding) *func(*UEContextResumeResponseIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextResumeResponseMMEUES1APIDIEBindingFieldInfo(v *UEContextResumeResponseMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeResponseMMEUES1APIDIEBindingFieldInject(v *UEContextResumeResponseMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextResumeResponseIEValue {
	return &v.inject
}
func BridgeUEContextResumeResponsePendingDataIndicationIEBindingFieldCodec(v *UEContextResumeResponsePendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeUEContextResumeResponsePendingDataIndicationIEBindingFieldGet(v *UEContextResumeResponsePendingDataIndicationIEBinding) *func(*UEContextResumeResponseIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeUEContextResumeResponsePendingDataIndicationIEBindingFieldInfo(v *UEContextResumeResponsePendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextResumeResponsePendingDataIndicationIEBindingFieldInject(v *UEContextResumeResponsePendingDataIndicationIEBinding) *func(s00.PendingDataIndication) UEContextResumeResponseIEValue {
	return &v.inject
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCapture(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *func(X2TNLConfigurationInfoExtIEsExtContainer, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCompare(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *func(X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldContext(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldDecode(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldEncode(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *func(X2TNLConfigurationInfoExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldPath(v *X2TNLConfigurationInfoExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v *X2TNLConfigurationInfoExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v *X2TNLConfigurationInfoExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(v *X2TNLConfigurationInfoExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(v *X2TNLConfigurationInfoExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCapture(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *func(X2TNLConfigurationInfoExtIEsExtField, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCompare(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *func(X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldContext(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldDecode(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (X2TNLConfigurationInfoExtIEsExtField, error) {
	return &v.decode
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldEncode(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *func(X2TNLConfigurationInfoExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldPath(v *X2TNLConfigurationInfoExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeX2TNLConfigurationInfoExtIEsValueFieldId(v *X2TNLConfigurationInfoExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeX2TNLConfigurationInfoExtIEsValueFieldIsOpaque(v *X2TNLConfigurationInfoExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeX2TNLConfigurationInfoExtIEsValueFieldOpaque(v *X2TNLConfigurationInfoExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBIndirectX2TransportLayerAddresses(v *X2TNLConfigurationInfoExtIEsValue) **s00.ENBIndirectX2TransportLayerAddresses {
	return &v.rowENBIndirectX2TransportLayerAddresses
}
func BridgeX2TNLConfigurationInfoExtIEsValueFieldRowENBX2ExtendedTransportLayerAddresses(v *X2TNLConfigurationInfoExtIEsValue) **s18.ENBX2ExtTLAs {
	return &v.rowENBX2ExtendedTransportLayerAddresses
}
func BridgeX2TNLConfigurationInfoExtIEsValueMethodCaptureSemantics(v X2TNLConfigurationInfoExtIEsValue, a0 aper.SemanticCapture) X2TNLConfigurationInfoExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeX2TNLConfigurationInfoExtIEsValueMethodCompareSemantics(v X2TNLConfigurationInfoExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeX2TNLConfigurationInfoExtIEsValueMethodMatchesID(v X2TNLConfigurationInfoExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeX2TNLConfigurationInfoExtIEsValueMethodRule(v X2TNLConfigurationInfoExtIEsValue) aper.SourceRule {
	return v.rule()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UEContextResumeRequestIEValue) Selected() (any, bool) {
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
	case 235:
		if value, ok := v.AsERABFailedToResumeListResumeReq(); ok {
			return value, true
		}
	case 245:
		if value, ok := v.AsRRCResumeCause(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *UEContextResumeResponseIEValue) Selected() (any, bool) {
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
	case 237:
		if value, ok := v.AsERABFailedToResumeListResumeRes(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 40:
		if value, ok := v.AsSecurityContext(); ok {
			return value, true
		}
	case 283:
		if value, ok := v.AsPendingDataIndication(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *X2TNLConfigurationInfoExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 153:
		if value, ok := v.AsENBX2ExtendedTransportLayerAddresses(); ok {
			return value, true
		}
	case 193:
		if value, ok := v.AsENBIndirectX2TransportLayerAddresses(); ok {
			return value, true
		}
	}
	return nil, false
}
