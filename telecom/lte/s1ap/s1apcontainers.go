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

// ProtocolIEContainer represents the ASN.1 type ProtocolIE-Container (SEQUENCE_OF).
type ProtocolIEContainer = []ProtocolIEField

// ProtocolIESingleContainer represents the ASN.1 type ProtocolIE-SingleContainer (SEQUENCE).
type ProtocolIESingleContainer struct {
	Id          ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality Criticality      `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEField represents the ASN.1 type ProtocolIE-Field (SEQUENCE).
type ProtocolIEField struct {
	Id          ProtocolIEID     `asn1:"tag:0,context,implicit"`
	Criticality Criticality      `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEContainerPair represents the ASN.1 type ProtocolIE-ContainerPair (SEQUENCE_OF).
type ProtocolIEContainerPair = []ProtocolIEFieldPair

// ProtocolIEFieldPair represents the ASN.1 type ProtocolIE-FieldPair (SEQUENCE).
type ProtocolIEFieldPair struct {
	Id                ProtocolIEID     `asn1:"tag:0,context,implicit"`
	FirstCriticality  Criticality      `asn1:"tag:1,context,implicit"`
	FirstValue        runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	SecondCriticality Criticality      `asn1:"tag:3,context,implicit"`
	SecondValue       runtime.RawValue `asn1:"tag:4,context,explicit" asn1c:"raw-preserve"`
}

// ProtocolIEContainerList represents the ASN.1 type ProtocolIE-ContainerList (SEQUENCE_OF).
type ProtocolIEContainerList = []ProtocolIESingleContainer

// ProtocolIEContainerPairList represents the ASN.1 type ProtocolIE-ContainerPairList (SEQUENCE_OF).
type ProtocolIEContainerPairList = []ProtocolIEContainerPair

// ProtocolExtensionContainer represents the ASN.1 type ProtocolExtensionContainer (SEQUENCE_OF).
type ProtocolExtensionContainer = []ProtocolExtensionField

// ProtocolExtensionField represents the ASN.1 type ProtocolExtensionField (SEQUENCE).
type ProtocolExtensionField struct {
	Id             ProtocolExtensionID `asn1:"tag:0,context,implicit"`
	Criticality    Criticality         `asn1:"tag:1,context,implicit"`
	ExtensionValue runtime.RawValue    `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// PrivateIEContainer represents the ASN.1 type PrivateIE-Container (SEQUENCE_OF).
type PrivateIEContainer = []PrivateIEField

// PrivateIEField represents the ASN.1 type PrivateIE-Field (SEQUENCE).
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolIEContainerTo appends a ProtocolIEContainer list to bb.
func MarshalAPERProtocolIEContainerTo(list ProtocolIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERProtocolIEContainer decodes a ProtocolIEContainer list from APER.
func UnmarshalAPERProtocolIEContainer(data []byte) (ProtocolIEContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainer")
	}
	return value, nil
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
	v.Value = make(ProtocolIEContainer, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ProtocolIESingleContainer to APER format.
func (v *ProtocolIESingleContainer) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
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
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIESingleContainer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIESingleContainer")
	}
	return nil
}

func (v *ProtocolIESingleContainer) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ProtocolIESingleContainer{}
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = ProtocolIEID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
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
	return bb.CompleteBytes(), nil
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
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEField")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEField")
	}
	return nil
}

func (v *ProtocolIEField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ProtocolIEField{}
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = ProtocolIEID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolIEContainerPairTo appends a ProtocolIEContainerPair list to bb.
func MarshalAPERProtocolIEContainerPairTo(list ProtocolIEContainerPair, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerPair decodes a ProtocolIEContainerPair list from APER.
func UnmarshalAPERProtocolIEContainerPair(data []byte) (ProtocolIEContainerPair, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerPairFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerPair")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerPair")
	}
	return value, nil
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
	v.Value = make(ProtocolIEContainerPair, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIEFieldPair
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ProtocolIEFieldPair to APER format.
func (v *ProtocolIEFieldPair) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
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
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEFieldPair")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEFieldPair")
	}
	return nil
}

func (v *ProtocolIEFieldPair) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ProtocolIEFieldPair{}
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = ProtocolIEID(val_id)
	val_firstcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "FirstCriticality")
	}
	v.FirstCriticality = Criticality(val_firstcriticality)
	openData_firstvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "FirstValue")
	}
	v.FirstValue = runtime.RawValue{Bytes: openData_firstvalue}
	val_secondcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "SecondCriticality")
	}
	v.SecondCriticality = Criticality(val_secondcriticality)
	openData_secondvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "SecondValue")
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolIEContainerListTo appends a ProtocolIEContainerList list to bb.
func MarshalAPERProtocolIEContainerListTo(list ProtocolIEContainerList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerList decodes a ProtocolIEContainerList list from APER.
func UnmarshalAPERProtocolIEContainerList(data []byte) (ProtocolIEContainerList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerList")
	}
	return value, nil
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
	v.Value = make(ProtocolIEContainerList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolIESingleContainer
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolIEContainerPairListTo appends a ProtocolIEContainerPairList list to bb.
func MarshalAPERProtocolIEContainerPairListTo(list ProtocolIEContainerPairList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, outerElem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := MarshalAPERProtocolIEContainerPairTo(outerElem, bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERProtocolIEContainerPairList decodes a ProtocolIEContainerPairList list from APER.
func UnmarshalAPERProtocolIEContainerPairList(data []byte) (ProtocolIEContainerPairList, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerPairListFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerPairList")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolIEContainerPairList")
	}
	return value, nil
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
	v.Value = make(ProtocolIEContainerPairList, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i_value := int64(0); i_value < fragmentLength_value; i_value++ {
			elem, err := UnmarshalAPERProtocolIEContainerPairFrom(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i_value))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERProtocolExtensionContainerTo appends a ProtocolExtensionContainer list to bb.
func MarshalAPERProtocolExtensionContainerTo(list ProtocolExtensionContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolExtensionContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERProtocolExtensionContainer decodes a ProtocolExtensionContainer list from APER.
func UnmarshalAPERProtocolExtensionContainer(data []byte) (ProtocolExtensionContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolExtensionContainerFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
	}
	return value, nil
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
	v.Value = make(ProtocolExtensionContainer, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ProtocolExtensionField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes ProtocolExtensionField to APER format.
func (v *ProtocolExtensionField) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
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
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolExtensionField")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "ProtocolExtensionField")
	}
	return nil
}

func (v *ProtocolExtensionField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = ProtocolExtensionField{}
	val_id, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = ProtocolExtensionID(val_id)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_extensionvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %v: %w", v.Id, err), "ExtensionValue")
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
	return bb.CompleteBytes(), nil
}

// MarshalAPERPrivateIEContainerTo appends a PrivateIEContainer list to bb.
func MarshalAPERPrivateIEContainerTo(list PrivateIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERPrivateIEContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalAPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERPrivateIEContainer decodes a PrivateIEContainer list from APER.
func UnmarshalAPERPrivateIEContainer(data []byte) (PrivateIEContainer, error) {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERPrivateIEContainerFrom(bb)
	if err != nil {
		return nil, runtime.WrapDecodePath(err, "PrivateIEContainer")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return nil, runtime.WrapDecodePath(err, "PrivateIEContainer")
	}
	return value, nil
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
	v.Value = make(PrivateIEContainer, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem PrivateIEField
			if err := elem.UnmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes PrivateIEField to APER format.
func (v *PrivateIEField) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
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
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEField")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEField")
	}
	return nil
}

func (v *PrivateIEField) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = PrivateIEField{}
	if err := v.Id.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("id %v: %w", v.Id, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}
