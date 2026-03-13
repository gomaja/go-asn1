// Package tag provides ASN.1 tag definitions and utilities.
package tag

import "fmt"

// Class represents an ASN.1 tag class.
type Class uint8

const (
	ClassUniversal       Class = 0
	ClassApplication     Class = 1
	ClassContextSpecific Class = 2
	ClassPrivate         Class = 3
)

func (c Class) String() string {
	switch c {
	case ClassUniversal:
		return "UNIVERSAL"
	case ClassApplication:
		return "APPLICATION"
	case ClassContextSpecific:
		return "CONTEXT"
	case ClassPrivate:
		return "PRIVATE"
	default:
		return fmt.Sprintf("CLASS(%d)", c)
	}
}

// Universal tag numbers as defined in X.680.
const (
	TagBoolean         = 1
	TagInteger         = 2
	TagBitString       = 3
	TagOctetString     = 4
	TagNull            = 5
	TagObjectID        = 6
	TagObjectDesc      = 7
	TagExternal        = 8
	TagReal            = 9
	TagEnumerated      = 10
	TagEmbeddedPDV     = 11
	TagUTF8String      = 12
	TagRelativeOID     = 13
	TagSequence        = 16
	TagSet             = 17
	TagNumericString   = 18
	TagPrintableString = 19
	TagT61String       = 20
	TagVideotexString  = 21
	TagIA5String       = 22
	TagUTCTime         = 23
	TagGeneralizedTime = 24
	TagGraphicString   = 25
	TagVisibleString   = 26
	TagGeneralString   = 27
	TagUniversalString = 28
	TagBMPString       = 30
)

// Tag represents a fully decoded ASN.1 tag.
type Tag struct {
	Class       Class
	Number      int
	Constructed bool
}

// Equal returns true if two tags have the same class and number.
func (t Tag) Equal(other Tag) bool {
	return t.Class == other.Class && t.Number == other.Number
}

func (t Tag) String() string {
	form := "PRIMITIVE"
	if t.Constructed {
		form = "CONSTRUCTED"
	}
	return fmt.Sprintf("[%s %d %s]", t.Class, t.Number, form)
}

// Encode serializes the tag to bytes per X.690 section 8.1.2.
func (t Tag) Encode() []byte {
	firstByte := byte(t.Class) << 6
	if t.Constructed {
		firstByte |= 0x20
	}

	if t.Number < 31 {
		return []byte{firstByte | byte(t.Number)}
	}

	// Long form: first byte has 11111 in low bits, then base-128 encoding.
	firstByte |= 0x1F
	result := []byte{firstByte}

	// Encode tag number in base-128, high bit set on all but last byte.
	num := t.Number
	var encoded []byte
	for num > 0 {
		encoded = append([]byte{byte(num & 0x7F)}, encoded...)
		num >>= 7
	}
	for i := 0; i < len(encoded)-1; i++ {
		encoded[i] |= 0x80
	}
	return append(result, encoded...)
}
