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
	Id                   ProtocolIEID                   `asn1:"tag:0,context,implicit"`
	Criticality          Criticality                    `asn1:"tag:1,context,implicit"`
	Value                runtime.RawValue               `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ProtocolIEField represents the ASN.1 type ProtocolIE-Field (SEQUENCE).
type ProtocolIEField struct {
	Id                   ProtocolIEID                   `asn1:"tag:0,context,implicit"`
	Criticality          Criticality                    `asn1:"tag:1,context,implicit"`
	Value                runtime.RawValue               `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ProtocolIEContainerPair represents the ASN.1 type ProtocolIE-ContainerPair (SEQUENCE_OF).

type ProtocolIEContainerPair = []ProtocolIEFieldPair

// ProtocolIEFieldPair represents the ASN.1 type ProtocolIE-FieldPair (SEQUENCE).
type ProtocolIEFieldPair struct {
	Id                   ProtocolIEID                   `asn1:"tag:0,context,implicit"`
	FirstCriticality     Criticality                    `asn1:"tag:1,context,implicit"`
	FirstValue           runtime.RawValue               `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	SecondCriticality    Criticality                    `asn1:"tag:3,context,implicit"`
	SecondValue          runtime.RawValue               `asn1:"tag:4,context,explicit" asn1c:"raw-preserve"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// ProtocolIEContainerList represents the ASN.1 type ProtocolIE-ContainerList (SEQUENCE_OF).

type ProtocolIEContainerList = []ProtocolIESingleContainer

// ProtocolIEContainerPairList represents the ASN.1 type ProtocolIE-ContainerPairList (SEQUENCE_OF).

type ProtocolIEContainerPairList = []ProtocolIEContainerPair

// ProtocolExtensionContainer represents the ASN.1 type ProtocolExtensionContainer (SEQUENCE_OF).

type ProtocolExtensionContainer = []ProtocolExtensionField

// ProtocolExtensionField represents the ASN.1 type ProtocolExtensionField (SEQUENCE).
type ProtocolExtensionField struct {
	Id                   ProtocolExtensionID            `asn1:"tag:0,context,implicit"`
	Criticality          Criticality                    `asn1:"tag:1,context,implicit"`
	ExtensionValue       runtime.RawValue               `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

// PrivateIEContainer represents the ASN.1 type PrivateIE-Container (SEQUENCE_OF).

type PrivateIEContainer = []PrivateIEField

// PrivateIEField represents the ASN.1 type PrivateIE-Field (SEQUENCE).
type PrivateIEField struct {
	Id                   PrivateIEID                    `asn1:"tag:0,context,explicit"`
	Criticality          Criticality                    `asn1:"tag:1,context,implicit"`
	Value                runtime.RawValue               `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	PERPadding_          per.CompletePadding            `asn1:"-" json:"-"`
	PERExtraBits_        per.TrailingBits               `asn1:"-" json:"-"`
	PERContainedPadding_ map[string]per.CompletePadding `asn1:"-" json:"-"`
}

type asn1cAPERProtocolIEContainerListValue struct{ Value ProtocolIEContainer }

// ProtocolIEContainerComplete carries a complete ProtocolIEContainer encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ProtocolIEContainerComplete struct {
	Value       ProtocolIEContainer
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ProtocolIEContainerComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ProtocolIEContainerComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainer")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainer")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERProtocolIEContainer encodes a ProtocolIEContainer list to APER.
func MarshalAPERProtocolIEContainer(list ProtocolIEContainerComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERProtocolIEContainerTo appends a ProtocolIEContainer list to bb.
func MarshalAPERProtocolIEContainerTo(list ProtocolIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERProtocolIEContainer(data []byte) (ProtocolIEContainerComplete, error) {
	var value ProtocolIEContainerComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1195
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIESingleContainer")
	}
	v.PERPadding_ = padding
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEField")
	}
	v.PERPadding_ = padding
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

// ProtocolIEContainerPairComplete carries a complete ProtocolIEContainerPair encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ProtocolIEContainerPairComplete struct {
	Value       ProtocolIEContainerPair
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ProtocolIEContainerPairComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerPairTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ProtocolIEContainerPairComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerPairFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerPair")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerPair")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERProtocolIEContainerPair encodes a ProtocolIEContainerPair list to APER.
func MarshalAPERProtocolIEContainerPair(list ProtocolIEContainerPairComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERProtocolIEContainerPairTo appends a ProtocolIEContainerPair list to bb.
func MarshalAPERProtocolIEContainerPairTo(list ProtocolIEContainerPair, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERProtocolIEContainerPair(data []byte) (ProtocolIEContainerPairComplete, error) {
	var value ProtocolIEContainerPairComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1195
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEFieldPair")
	}
	v.PERPadding_ = padding
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

// ProtocolIEContainerListComplete carries a complete ProtocolIEContainerList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ProtocolIEContainerListComplete struct {
	Value       ProtocolIEContainerList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ProtocolIEContainerListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ProtocolIEContainerListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERProtocolIEContainerList encodes a ProtocolIEContainerList list to APER.
func MarshalAPERProtocolIEContainerList(list ProtocolIEContainerListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERProtocolIEContainerListTo appends a ProtocolIEContainerList list to bb.
func MarshalAPERProtocolIEContainerListTo(list ProtocolIEContainerList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERProtocolIEContainerList(data []byte) (ProtocolIEContainerListComplete, error) {
	var value ProtocolIEContainerListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1195
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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

// ProtocolIEContainerPairListComplete carries a complete ProtocolIEContainerPairList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ProtocolIEContainerPairListComplete struct {
	Value       ProtocolIEContainerPairList
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ProtocolIEContainerPairListComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolIEContainerPairListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ProtocolIEContainerPairListComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolIEContainerPairListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerPairList")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolIEContainerPairList")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERProtocolIEContainerPairList encodes a ProtocolIEContainerPairList list to APER.
func MarshalAPERProtocolIEContainerPairList(list ProtocolIEContainerPairListComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERProtocolIEContainerPairListTo appends a ProtocolIEContainerPairList list to bb.
func MarshalAPERProtocolIEContainerPairListTo(list ProtocolIEContainerPairList, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolIEContainerPairListListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERProtocolIEContainerPairList(data []byte) (ProtocolIEContainerPairListComplete, error) {
	var value ProtocolIEContainerPairListComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_4: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1249
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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

// ProtocolExtensionContainerComplete carries a complete ProtocolExtensionContainer encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ProtocolExtensionContainerComplete struct {
	Value       ProtocolExtensionContainer
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *ProtocolExtensionContainerComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERProtocolExtensionContainerTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *ProtocolExtensionContainerComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERProtocolExtensionContainerFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolExtensionContainer")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERProtocolExtensionContainer encodes a ProtocolExtensionContainer list to APER.
func MarshalAPERProtocolExtensionContainer(list ProtocolExtensionContainerComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERProtocolExtensionContainerTo appends a ProtocolExtensionContainer list to bb.
func MarshalAPERProtocolExtensionContainerTo(list ProtocolExtensionContainer, bb *per.BitBuffer) error {
	v := asn1cAPERProtocolExtensionContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERProtocolExtensionContainer(data []byte) (ProtocolExtensionContainerComplete, error) {
	var value ProtocolExtensionContainerComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1195
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProtocolExtensionField")
	}
	v.PERPadding_ = padding
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

// PrivateIEContainerComplete carries a complete PrivateIEContainer encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PrivateIEContainerComplete struct {
	Value       PrivateIEContainer
	PERPadding_ per.CompletePadding `json:"-"`
}

func (v *PrivateIEContainerComplete) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalAPERPrivateIEContainerTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *PrivateIEContainerComplete) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	value, err := UnmarshalAPERPrivateIEContainerFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEContainer")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEContainer")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalAPERPrivateIEContainer encodes a PrivateIEContainer list to APER.
func MarshalAPERPrivateIEContainer(list PrivateIEContainerComplete) ([]byte, error) {
	return list.MarshalAPER()
}

// MarshalAPERPrivateIEContainerTo appends a PrivateIEContainer list to bb.
func MarshalAPERPrivateIEContainerTo(list PrivateIEContainer, bb *per.BitBuffer) error {
	v := asn1cAPERPrivateIEContainerListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
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
func UnmarshalAPERPrivateIEContainer(data []byte) (PrivateIEContainerComplete, error) {
	var value PrivateIEContainerComplete
	if err := value.UnmarshalAPER(data); err != nil {
		return value, err
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
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1195
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEField")
	}
	v.PERPadding_ = padding
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
