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
	Id          int64            `asn1:"tag:0,context,implicit"`
	Criticality int64            `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit"`
}

// ProtocolIEField represents the ASN.1 type ProtocolIE-Field (SEQUENCE).
type ProtocolIEField struct {
	Id          int64            `asn1:"tag:0,context,implicit"`
	Criticality int64            `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit"`
}

// ProtocolIEContainerPair represents the ASN.1 type ProtocolIE-ContainerPair (SEQUENCE_OF).
type ProtocolIEContainerPair = []ProtocolIEFieldPair

// ProtocolIEFieldPair represents the ASN.1 type ProtocolIE-FieldPair (SEQUENCE).
type ProtocolIEFieldPair struct {
	Id                int64            `asn1:"tag:0,context,implicit"`
	FirstCriticality  int64            `asn1:"tag:1,context,implicit"`
	FirstValue        runtime.RawValue `asn1:"tag:2,context,explicit"`
	SecondCriticality int64            `asn1:"tag:3,context,implicit"`
	SecondValue       runtime.RawValue `asn1:"tag:4,context,explicit"`
}

// ProtocolIEContainerList represents the ASN.1 type ProtocolIE-ContainerList (SEQUENCE_OF).
type ProtocolIEContainerList = []ProtocolIESingleContainer

// ProtocolIEContainerPairList represents the ASN.1 type ProtocolIE-ContainerPairList (SEQUENCE_OF).
type ProtocolIEContainerPairList = []ProtocolIEContainerPair

// ProtocolExtensionContainer represents the ASN.1 type ProtocolExtensionContainer (SEQUENCE_OF).
type ProtocolExtensionContainer = []ProtocolExtensionField

// ProtocolExtensionField represents the ASN.1 type ProtocolExtensionField (SEQUENCE).
type ProtocolExtensionField struct {
	Id             int64            `asn1:"tag:0,context,implicit"`
	Criticality    int64            `asn1:"tag:1,context,implicit"`
	ExtensionValue runtime.RawValue `asn1:"tag:2,context,explicit"`
}

// PrivateIEContainer represents the ASN.1 type PrivateIE-Container (SEQUENCE_OF).
type PrivateIEContainer = []PrivateIEField

// PrivateIEField represents the ASN.1 type PrivateIE-Field (SEQUENCE).
type PrivateIEField struct {
	Id          runtime.RawValue `asn1:"tag:0,context,explicit"`
	Criticality int64            `asn1:"tag:1,context,implicit"`
	Value       runtime.RawValue `asn1:"tag:2,context,explicit"`
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
	v.Id = val_id
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = val_criticality
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
	v.Id = val_id
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = val_criticality
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
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
	v.Id = val_id
	val_firstcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding firstCriticality: %w", err)
	}
	v.FirstCriticality = val_firstcriticality
	openData_firstvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding firstValue: %w", err)
	}
	v.FirstValue = runtime.RawValue{Bytes: openData_firstvalue}
	val_secondcriticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding secondCriticality: %w", err)
	}
	v.SecondCriticality = val_secondcriticality
	openData_secondvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding secondValue: %w", err)
	}
	v.SecondValue = runtime.RawValue{Bytes: openData_secondvalue}
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
	v.Id = val_id
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = val_criticality
	openData_extensionvalue, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding extensionValue: %w", err)
	}
	v.ExtensionValue = runtime.RawValue{Bytes: openData_extensionvalue}
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
	// asn1c:unsupported {"encoding":"aper","operation":"encode","construct":"CHOICE","reason":"inline-constructed-type","field":"id","kind":"CHOICE"}
	if err := per.EncodeOpenTypeAligned(bb, v.Id.Bytes); err != nil {
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
	// asn1c:unsupported {"encoding":"aper","operation":"decode","construct":"CHOICE","reason":"inline-constructed-type","field":"id","kind":"CHOICE"}
	openData_id, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding id: %w", err)
	}
	v.Id = runtime.RawValue{Bytes: openData_id}
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return fmt.Errorf("decoding criticality: %w", err)
	}
	v.Criticality = val_criticality
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return fmt.Errorf("decoding value: %w", err)
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}
