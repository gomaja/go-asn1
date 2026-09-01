// Code generated from ASN.1 module "S1AP-Containers". DO NOT EDIT.

package s1ap

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// ProtocolIEContainer represents the ASN.1 type ProtocolIEContainer (SEQUENCE_OF).
type ProtocolIEContainer = []ProtocolIEField

// ProtocolIESingleContainer represents the ASN.1 type ProtocolIESingleContainer (SEQUENCE).
type ProtocolIESingleContainer struct {
	Id          ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality Criticality      `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEField represents the ASN.1 type ProtocolIEField (SEQUENCE).
type ProtocolIEField struct {
	Id          ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality Criticality      `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEContainerPair represents the ASN.1 type ProtocolIEContainerPair (SEQUENCE_OF).
type ProtocolIEContainerPair = []ProtocolIEFieldPair

// ProtocolIEFieldPair represents the ASN.1 type ProtocolIEFieldPair (SEQUENCE).
type ProtocolIEFieldPair struct {
	Id                ProtocolIEID     `asn1:"tag:0,context,implicit"`
	FirstCriticality  Criticality      `asn1:"tag:1,context,implicit"`
	FirstValue        runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	SecondCriticality Criticality      `asn1:"tag:3,context,implicit"`
	SecondValue       runtime.RawValue `asn1:"tag:4,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEContainerList represents the ASN.1 type ProtocolIEContainerList (SEQUENCE_OF).
type ProtocolIEContainerList = []ProtocolIESingleContainer

// ProtocolIEContainerPairList represents the ASN.1 type ProtocolIEContainerPairList (SEQUENCE_OF).
type ProtocolIEContainerPairList = []ProtocolIEContainerPair

// ProtocolExtensionContainer represents the ASN.1 type ProtocolExtensionContainer (SEQUENCE_OF).
type ProtocolExtensionContainer = []ProtocolExtensionField

// ProtocolExtensionField represents the ASN.1 type ProtocolExtensionField (SEQUENCE).
type ProtocolExtensionField struct {
	Id             ProtocolExtensionID `asn1:"tag:0,context,implicit"`
	Criticality    Criticality         `asn1:"tag:1,context,implicit"`
	ExtensionValue runtime.RawValue    `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// PrivateIEContainer represents the ASN.1 type PrivateIEContainer (SEQUENCE_OF).
type PrivateIEContainer = []PrivateIEField

// PrivateIEField represents the ASN.1 type PrivateIEField (SEQUENCE).
type PrivateIEField struct {
	Id          PrivateIEID      `asn1:"tag:0,context,explicit"`
	Criticality Criticality      `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

type asn1cAPERProtocolIEContainerListValue struct{ Value ProtocolIEContainer }

// MarshalAPERProtocolIEContainer encodes a ProtocolIEContainer list to APER.
func MarshalAPERProtocolIEContainer(list ProtocolIEContainer) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERProtocolIEContainerTo appends a ProtocolIEContainer list to bb.
func MarshalAPERProtocolIEContainerTo(list ProtocolIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(len(v.Value)), 0, 65535); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERProtocolIEContainer decodes a ProtocolIEContainer list from APER.
func UnmarshalAPERProtocolIEContainer(data []byte) (ProtocolIEContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERProtocolIEContainerFrom(bb)
}

// UnmarshalAPERProtocolIEContainerFrom decodes a ProtocolIEContainer list from bb.
func UnmarshalAPERProtocolIEContainerFrom(bb *per.BitBuffer) (ProtocolIEContainer, error) {
	var v asn1cAPERProtocolIEContainerListValue
	if err := unmarshalAPERProtocolIEContainerInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolIEContainerInto(v *asn1cAPERProtocolIEContainerListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumberAligned(bb, 0, 65535)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 0 {
		return fmt.Errorf("decoding value length %d below lower bound 0", seqLen_value)
	}
	if seqLen_value > 65535 {
		return fmt.Errorf("decoding value length %d above upper bound 65535", seqLen_value)
	}
	v.Value = make(ProtocolIEContainer, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalAPER encodes ProtocolIESingleContainer to APER format.
func (v *ProtocolIESingleContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ProtocolIESingleContainer) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.Id), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes ProtocolIESingleContainer from APER format.
func (v *ProtocolIESingleContainer) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *ProtocolIESingleContainer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	v.Id = ProtocolIEID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}

// MarshalAPER encodes ProtocolIEField to APER format.
func (v *ProtocolIEField) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ProtocolIEField) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.Id), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes ProtocolIEField from APER format.
func (v *ProtocolIEField) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *ProtocolIEField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	v.Id = ProtocolIEID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}

type asn1cAPERProtocolIEContainerPairListValue struct{ Value ProtocolIEContainerPair }

// MarshalAPERProtocolIEContainerPair encodes a ProtocolIEContainerPair list to APER.
func MarshalAPERProtocolIEContainerPair(list ProtocolIEContainerPair) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerPairTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERProtocolIEContainerPairTo appends a ProtocolIEContainerPair list to bb.
func MarshalAPERProtocolIEContainerPairTo(list ProtocolIEContainerPair, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(len(v.Value)), 0, 65535); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerPair decodes a ProtocolIEContainerPair list from APER.
func UnmarshalAPERProtocolIEContainerPair(data []byte) (ProtocolIEContainerPair, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERProtocolIEContainerPairFrom(bb)
}

// UnmarshalAPERProtocolIEContainerPairFrom decodes a ProtocolIEContainerPair list from bb.
func UnmarshalAPERProtocolIEContainerPairFrom(bb *per.BitBuffer) (ProtocolIEContainerPair, error) {
	var v asn1cAPERProtocolIEContainerPairListValue
	if err := unmarshalAPERProtocolIEContainerPairInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolIEContainerPairInto(v *asn1cAPERProtocolIEContainerPairListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumberAligned(bb, 0, 65535)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 0 {
		return fmt.Errorf("decoding value length %d below lower bound 0", seqLen_value)
	}
	if seqLen_value > 65535 {
		return fmt.Errorf("decoding value length %d above upper bound 65535", seqLen_value)
	}
	v.Value = make(ProtocolIEContainerPair, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalAPER encodes ProtocolIEFieldPair to APER format.
func (v *ProtocolIEFieldPair) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ProtocolIEFieldPair) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.Id), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.FirstCriticality), 3, false); err != nil {
		return fmt.Errorf("encoding firstCriticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.FirstValue.Bytes); err != nil {
		return fmt.Errorf("encoding firstValue: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.SecondCriticality), 3, false); err != nil {
		return fmt.Errorf("encoding secondCriticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.SecondValue.Bytes); err != nil {
		return fmt.Errorf("encoding secondValue: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes ProtocolIEFieldPair from APER format.
func (v *ProtocolIEFieldPair) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *ProtocolIEFieldPair) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	v.Id = ProtocolIEID(val_id)
	val_firstcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding firstCriticality: %w", err)
	}
	v.FirstCriticality = Criticality(val_firstcriticality)
	openData_firstvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding firstValue: %w", err)
	}
	v.FirstValue = runtime.RawValue{Bytes: openData_firstvalue}
	val_secondcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding secondCriticality: %w", err)
	}
	v.SecondCriticality = Criticality(val_secondcriticality)
	openData_secondvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding secondValue: %w", err)
	}
	v.SecondValue = runtime.RawValue{Bytes: openData_secondvalue}
	return nil
}

type asn1cAPERProtocolIEContainerListListValue struct{ Value ProtocolIEContainerList }

// MarshalAPERProtocolIEContainerList encodes a ProtocolIEContainerList list to APER.
func MarshalAPERProtocolIEContainerList(list ProtocolIEContainerList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERProtocolIEContainerListTo appends a ProtocolIEContainerList list to bb.
func MarshalAPERProtocolIEContainerListTo(list ProtocolIEContainerList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListListValue{Value: list}
	if err := per.EncodeLengthAligned(bb, int64(len(v.Value)), false); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerList decodes a ProtocolIEContainerList list from APER.
func UnmarshalAPERProtocolIEContainerList(data []byte) (ProtocolIEContainerList, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERProtocolIEContainerListFrom(bb)
}

// UnmarshalAPERProtocolIEContainerListFrom decodes a ProtocolIEContainerList list from bb.
func UnmarshalAPERProtocolIEContainerListFrom(bb *per.BitBuffer) (ProtocolIEContainerList, error) {
	var v asn1cAPERProtocolIEContainerListListValue
	if err := unmarshalAPERProtocolIEContainerListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolIEContainerListInto(v *asn1cAPERProtocolIEContainerListListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeLengthAligned(bb, false)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	v.Value = make(ProtocolIEContainerList, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

type asn1cAPERProtocolIEContainerPairListListValue struct{ Value ProtocolIEContainerPairList }

// MarshalAPERProtocolIEContainerPairList encodes a ProtocolIEContainerPairList list to APER.
func MarshalAPERProtocolIEContainerPairList(list ProtocolIEContainerPairList) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerPairListTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERProtocolIEContainerPairListTo appends a ProtocolIEContainerPairList list to bb.
func MarshalAPERProtocolIEContainerPairListTo(list ProtocolIEContainerPairList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListListValue{Value: list}
	if err := per.EncodeLengthAligned(bb, int64(len(v.Value)), false); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, outerElem := range v.Value {
		if err := MarshalAPERProtocolIEContainerPairTo(outerElem, bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerPairList decodes a ProtocolIEContainerPairList list from APER.
func UnmarshalAPERProtocolIEContainerPairList(data []byte) (ProtocolIEContainerPairList, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERProtocolIEContainerPairListFrom(bb)
}

// UnmarshalAPERProtocolIEContainerPairListFrom decodes a ProtocolIEContainerPairList list from bb.
func UnmarshalAPERProtocolIEContainerPairListFrom(bb *per.BitBuffer) (ProtocolIEContainerPairList, error) {
	var v asn1cAPERProtocolIEContainerPairListListValue
	if err := unmarshalAPERProtocolIEContainerPairListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolIEContainerPairListInto(v *asn1cAPERProtocolIEContainerPairListListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeLengthAligned(bb, false)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	v.Value = make(ProtocolIEContainerPairList, seqLen_value)
	for i_value := int64(0); i_value < seqLen_value; i_value++ {
		elem, err := UnmarshalAPERProtocolIEContainerPairFrom(bb)
		if err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
		v.Value[i_value] = elem
	}
	return nil
}

type asn1cAPERProtocolExtensionContainerListValue struct{ Value ProtocolExtensionContainer }

// MarshalAPERProtocolExtensionContainer encodes a ProtocolExtensionContainer list to APER.
func MarshalAPERProtocolExtensionContainer(list ProtocolExtensionContainer) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolExtensionContainerTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERProtocolExtensionContainerTo appends a ProtocolExtensionContainer list to bb.
func MarshalAPERProtocolExtensionContainerTo(list ProtocolExtensionContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolExtensionContainerListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(len(v.Value)), 1, 65535); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERProtocolExtensionContainer decodes a ProtocolExtensionContainer list from APER.
func UnmarshalAPERProtocolExtensionContainer(data []byte) (ProtocolExtensionContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERProtocolExtensionContainerFrom(bb)
}

// UnmarshalAPERProtocolExtensionContainerFrom decodes a ProtocolExtensionContainer list from bb.
func UnmarshalAPERProtocolExtensionContainerFrom(bb *per.BitBuffer) (ProtocolExtensionContainer, error) {
	var v asn1cAPERProtocolExtensionContainerListValue
	if err := unmarshalAPERProtocolExtensionContainerInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERProtocolExtensionContainerInto(v *asn1cAPERProtocolExtensionContainerListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumberAligned(bb, 1, 65535)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 65535 {
		return fmt.Errorf("decoding value length %d above upper bound 65535", seqLen_value)
	}
	v.Value = make(ProtocolExtensionContainer, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalAPER encodes ProtocolExtensionField to APER format.
func (v *ProtocolExtensionField) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *ProtocolExtensionField) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.Id), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.ExtensionValue.Bytes); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes ProtocolExtensionField from APER format.
func (v *ProtocolExtensionField) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *ProtocolExtensionField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	v.Id = ProtocolExtensionID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = Criticality(val_criticality)
	openData_extensionvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding extensionValue: %w", err)
	}
	v.ExtensionValue = runtime.RawValue{Bytes: openData_extensionvalue}
	return nil
}

type asn1cAPERPrivateIEContainerListValue struct{ Value PrivateIEContainer }

// MarshalAPERPrivateIEContainer encodes a PrivateIEContainer list to APER.
func MarshalAPERPrivateIEContainer(list PrivateIEContainer) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERPrivateIEContainerTo(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

// MarshalAPERPrivateIEContainerTo appends a PrivateIEContainer list to bb.
func MarshalAPERPrivateIEContainerTo(list PrivateIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERPrivateIEContainerListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(len(v.Value)), 1, 65535); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalAPERPrivateIEContainer decodes a PrivateIEContainer list from APER.
func UnmarshalAPERPrivateIEContainer(data []byte) (PrivateIEContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	return UnmarshalAPERPrivateIEContainerFrom(bb)
}

// UnmarshalAPERPrivateIEContainerFrom decodes a PrivateIEContainer list from bb.
func UnmarshalAPERPrivateIEContainerFrom(bb *per.BitBuffer) (PrivateIEContainer, error) {
	var v asn1cAPERPrivateIEContainerListValue
	if err := unmarshalAPERPrivateIEContainerInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalAPERPrivateIEContainerInto(v *asn1cAPERPrivateIEContainerListValue, bb *per.BitBuffer) error {
	var seqLen_value int64
	var errLength_value error
	seqLen_value, errLength_value = per.DecodeConstrainedWholeNumberAligned(bb, 1, 65535)
	if errLength_value != nil {
		return fmt.Errorf("decoding value length: %w", errLength_value)
	}
	if seqLen_value < 1 {
		return fmt.Errorf("decoding value length %d below lower bound 1", seqLen_value)
	}
	if seqLen_value > 65535 {
		return fmt.Errorf("decoding value length %d above upper bound 65535", seqLen_value)
	}
	v.Value = make(PrivateIEContainer, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalAPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}

// MarshalAPER encodes PrivateIEField to APER format.
func (v *PrivateIEField) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *PrivateIEField) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := v.Id.MarshalAPERTo(bb); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes PrivateIEField from APER format.
func (v *PrivateIEField) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalAPERFrom(bb)
}

func (v *PrivateIEField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	if err := v.Id.UnmarshalAPERFrom(bb); err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}
