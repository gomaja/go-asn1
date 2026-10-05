package per

import "testing"

// A present empty OCTET STRING or BIT STRING decodes to a non-nil empty
// slice: for an OPTIONAL component a nil slice means absent (go-asn1#91).
// The length-delimited paths (no upper bound, or one of 64K or more, X.691
// (02/2021) 11.9.4.2 and 11.9.3.8) used to return nil; the constrained paths
// never did. Neither may allocate for the empty value.
func TestPresentEmptyStringsAreNotNil(t *testing.T) {
	octets := map[string]func(*BitBuffer) ([]byte, error){
		"UPER unconstrained": func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringExt(bb, 0, 0, false, false) },
		"UPER SIZE(0..8)":    func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringExt(bb, 0, 8, true, false) },
		"UPER SIZE(0..70000)": func(bb *BitBuffer) ([]byte, error) {
			return DecodeOctetStringExt(bb, 0, 70000, true, false)
		},
		"APER unconstrained": func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringAlignedExt(bb, 0, 0, false, false) },
		"APER SIZE(0..8)":    func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringAlignedExt(bb, 0, 8, true, false) },
		"APER SIZE(0..70000)": func(bb *BitBuffer) ([]byte, error) {
			return DecodeOctetStringAlignedExt(bb, 0, 70000, true, false)
		},
	}
	for name, decode := range octets {
		value, err := decode(NewBitBufferFromBytes([]byte{0, 0, 0}))
		if err != nil || value == nil || len(value) != 0 {
			t.Errorf("OCTET STRING %s: %v (nil %v), %v", name, value, value == nil, err)
		}
		bb := NewBitBufferFromBytes([]byte{0, 0, 0})
		if allocs := testing.AllocsPerRun(100, func() {
			bb.bitPos = 0
			if _, err := decode(bb); err != nil {
				t.Fatal(err)
			}
		}); allocs != 0 {
			t.Errorf("OCTET STRING %s: empty decode allocates %.0f times", name, allocs)
		}
	}
	// SIZE(1..8,...) with the extension bit set: an empty value outside the
	// root takes the unconstrained length (11.9.4.2, 11.9.3.8).
	for name, decode := range map[string]func(*BitBuffer) ([]byte, error){
		"UPER": func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringExt(bb, 1, 8, true, true) },
		"APER": func(bb *BitBuffer) ([]byte, error) { return DecodeOctetStringAlignedExt(bb, 1, 8, true, true) },
	} {
		if value, err := decode(NewBitBufferFromBytes([]byte{0x80, 0x00, 0x00})); err != nil || value == nil || len(value) != 0 {
			t.Errorf("OCTET STRING %s SIZE(1..8,...) outside root: %v (nil %v), %v", name, value, value == nil, err)
		}
	}
	bits := map[string]func(*BitBuffer) ([]byte, int, error){
		"UPER unconstrained": func(bb *BitBuffer) ([]byte, int, error) { return DecodeBitStringExt(bb, 0, 0, false, false) },
		"UPER SIZE(0..8)":    func(bb *BitBuffer) ([]byte, int, error) { return DecodeBitStringExt(bb, 0, 8, true, false) },
		"UPER SIZE(0..70000)": func(bb *BitBuffer) ([]byte, int, error) {
			return DecodeBitStringExt(bb, 0, 70000, true, false)
		},
		"APER unconstrained": func(bb *BitBuffer) ([]byte, int, error) { return DecodeBitStringAlignedExt(bb, 0, 0, false, false) },
		"APER SIZE(0..8)":    func(bb *BitBuffer) ([]byte, int, error) { return DecodeBitStringAlignedExt(bb, 0, 8, true, false) },
		"APER SIZE(0..70000)": func(bb *BitBuffer) ([]byte, int, error) {
			return DecodeBitStringAlignedExt(bb, 0, 70000, true, false)
		},
	}
	for name, decode := range bits {
		value, length, err := decode(NewBitBufferFromBytes([]byte{0, 0, 0}))
		if err != nil || value == nil || len(value) != 0 || length != 0 {
			t.Errorf("BIT STRING %s: %v/%d (nil %v), %v", name, value, length, value == nil, err)
		}
		bb := NewBitBufferFromBytes([]byte{0, 0, 0})
		if allocs := testing.AllocsPerRun(100, func() {
			bb.bitPos = 0
			if _, _, err := decode(bb); err != nil {
				t.Fatal(err)
			}
		}); allocs != 0 {
			t.Errorf("BIT STRING %s: empty decode allocates %.0f times", name, allocs)
		}
	}
}
