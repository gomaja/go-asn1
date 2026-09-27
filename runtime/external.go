package runtime

import (
	"math/big"
	"reflect"
)

// ExternalEncoding selects the X.690 (02/2021) §8.18 encoding alternative.
type ExternalEncoding uint8

const (
	ExternalSingleASN1Type ExternalEncoding = iota + 1
	ExternalOctetAligned
	ExternalArbitrary
)

// External represents the fields of the BER EXTERNAL value in X.690 §8.18.1.
// SingleASN1Type is an open value: its complete inner TLV remains raw until
// the direct or indirect reference identifies a schema for it.
type External struct {
	DirectReference     ObjectIdentifier
	IndirectReference   *big.Int
	DataValueDescriptor *string
	Encoding            ExternalEncoding
	SingleASN1Type      RawValue
	OctetAligned        []byte
	Arbitrary           BitString
	originalBER         []byte
	originalFields      *External
}

func (e External) fieldsCopy() External {
	e.originalBER = nil
	e.originalFields = nil
	e.DirectReference = append(ObjectIdentifier(nil), e.DirectReference...)
	if e.IndirectReference != nil {
		e.IndirectReference = new(big.Int).Set(e.IndirectReference)
	}
	if e.DataValueDescriptor != nil {
		value := *e.DataValueDescriptor
		e.DataValueDescriptor = &value
	}
	e.SingleASN1Type.Bytes = append([]byte(nil), e.SingleASN1Type.Bytes...)
	e.OctetAligned = append([]byte(nil), e.OctetAligned...)
	e.Arbitrary.Bytes = append([]byte(nil), e.Arbitrary.Bytes...)
	return e
}

// RememberBER preserves the original form for an unchanged decoded value.
func (e *External) RememberBER(wire []byte) {
	copy := e.fieldsCopy()
	e.originalFields = &copy
	e.originalBER = append([]byte(nil), wire...)
}

// UnchangedBER returns the original BER if no typed field was modified.
func (e External) UnchangedBER() []byte {
	if e.originalFields != nil && reflect.DeepEqual(e.fieldsCopy(), *e.originalFields) {
		return append([]byte(nil), e.originalBER...)
	}
	return nil
}
