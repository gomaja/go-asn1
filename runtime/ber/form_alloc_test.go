package ber

import (
	"encoding/hex"
	"testing"
)

// BenchmarkCanonical decodes a canonical primitive OCTET STRING with the
// form marker every generated BER decoder installs.
func BenchmarkCanonical(b *testing.B) {
	wire := []byte{4, 1, 7}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		opts := TrackBERForm(nil)
		if _, _, err := DecodeOctetString(wire, opts...); err != nil {
			b.Fatal(err)
		}
	}
}

// Form tracking must not make string decoding allocate more. The ceilings
// are the allocations per call at 5c356c4, before the decoders forwarded the
// form marker.
func TestTrackedDecodeAllocations(t *testing.T) {
	options := TrackBERForm(nil)
	for _, test := range []struct {
		name    string
		wire    string
		ceiling float64
		decode  func([]byte) error
	}{
		{"primitive OCTET STRING", "040107", 3, func(w []byte) error { _, _, err := DecodeOctetString(w, options...); return err }},
		{"constructed OCTET STRING", "2403040107", 6, func(w []byte) error { _, _, err := DecodeOctetString(w, options...); return err }},
		{"primitive BIT STRING", "030200ff", 3, func(w []byte) error { _, _, _, err := DecodeBitString(w, options...); return err }},
		{"implicit constructed BIT STRING", "030200ff", 4, func(w []byte) error { _, _, err := DecodeImplicitBitStringValue(true, w, options...); return err }},
		{"INTEGER", "020105", 1, func(w []byte) error { _, _, err := DecodeInteger(w, options...); return err }},
		{"TLV", "040107", 1, func(w []byte) error { _, _, _, err := DecodeTLV(w, options...); return err }},
	} {
		wire, err := hex.DecodeString(test.wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := test.decode(wire); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if allocs := testing.AllocsPerRun(200, func() { _ = test.decode(wire) }); allocs > test.ceiling {
			t.Errorf("%s: %.0f allocations per decode, base 5c356c4 made %.0f", test.name, allocs, test.ceiling)
		}
	}
}
