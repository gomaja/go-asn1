package ber

import "testing"

// A constructed OCTET STRING or BIT STRING may carry zero segments, or only
// empty ones (X.690 (02/2021) 8.6.3, 8.7.3). It is a present empty value and
// decodes to a non-nil empty slice, as the primitive form does: for an
// OPTIONAL component a nil slice means absent (go-asn1#91).
func TestConstructedEmptyStringsAreNotNil(t *testing.T) {
	for _, wire := range [][]byte{{0x04, 0x00}, {0x24, 0x00}, {0x24, 0x80, 0x00, 0x00}, {0x24, 0x02, 0x04, 0x00}} {
		value, _, err := DecodeOctetString(wire)
		if err != nil || value == nil || len(value) != 0 {
			t.Errorf("OCTET STRING %x: %v (nil %v), %v", wire, value, value == nil, err)
		}
	}
	if value, err := DecodeImplicitOctetStringValue(true, nil); err != nil || value == nil {
		t.Errorf("implicit constructed OCTET STRING: %v (nil %v), %v", value, value == nil, err)
	}
	for _, wire := range [][]byte{{0x03, 0x01, 0x00}, {0x23, 0x00}, {0x23, 0x80, 0x00, 0x00}, {0x23, 0x03, 0x03, 0x01, 0x00}} {
		value, unused, _, err := DecodeBitString(wire)
		if err != nil || value == nil || len(value) != 0 || unused != 0 {
			t.Errorf("BIT STRING %x: %v/%d (nil %v), %v", wire, value, unused, value == nil, err)
		}
	}
	if value, _, err := DecodeImplicitBitStringValue(true, nil); err != nil || value == nil {
		t.Errorf("implicit constructed BIT STRING: %v (nil %v), %v", value, value == nil, err)
	}
	// The empty result costs no allocation: an empty constructed value
	// allocates exactly what the primitive form does (the work budget).
	decodes := func(octets, bits []byte) float64 {
		return testing.AllocsPerRun(100, func() {
			if _, _, err := DecodeOctetString(octets); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := DecodeBitString(bits); err != nil {
				t.Fatal(err)
			}
		})
	}
	primitive, constructed := decodes([]byte{0x04, 0x00}, []byte{0x03, 0x01, 0x00}), decodes([]byte{0x24, 0x00}, []byte{0x23, 0x00})
	if constructed != primitive {
		t.Errorf("empty constructed decode allocates %.0f times, primitive %.0f", constructed, primitive)
	}
}
