package per

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// alignedStringVector is one BIT STRING or OCTET STRING field after or
// before a BOOLEAN TRUE, in the ALIGNED variant. The octets were derived
// field by field from ITU-T X.691 (02/2021) clauses 16 and 17; pycrate
// 0.7.11's decoder accepts all but the zero-length ones, where it expects
// padding that 11.9.3.3 NOTE 2 excludes. Wireshark 4.6's dissect_per_bit_string
// and dissect_per_octet_string also align only a non-empty value.
type alignedStringVector struct {
	name        string
	octets      bool
	trail       bool
	data        []byte
	bitLen      int
	lb, ub      int64
	constrained bool
	extensible  bool
	hex         string
}

var alignedStringVectors = []alignedStringVector{
	// go-asn1#102: 16.11 aligns every size that is not fixed.
	{name: "bits 0..8", data: []byte{0xa0}, bitLen: 3, lb: 0, ub: 8, constrained: true, hex: "98a0"},
	{name: "bits 1..16", data: []byte{0x80}, bitLen: 1, lb: 1, ub: 16, constrained: true, hex: "8080"},
	{name: "bits 1..17", data: []byte{0x80}, bitLen: 1, lb: 1, ub: 17, constrained: true, hex: "8080"},
	{name: "bits 0..8 empty", trail: true, data: []byte{}, bitLen: 0, lb: 0, ub: 8, constrained: true, hex: "08"},
	{name: "bits fixed 16", data: []byte{0xab, 0xcd}, bitLen: 16, lb: 16, ub: 16, constrained: true, hex: "d5e680"},
	{name: "bits fixed 17", data: []byte{0xd5, 0xe6, 0x80}, bitLen: 17, lb: 17, ub: 17, constrained: true, hex: "80d5e680"},
	{name: "bits 1..8 root", data: []byte{0xc0}, bitLen: 2, lb: 1, ub: 8, constrained: true, extensible: true, hex: "88c0"},
	{name: "bits 1..8 extension", data: []byte{0xff, 0x80}, bitLen: 9, lb: 1, ub: 8, constrained: true, extensible: true, hex: "c009ff80"},
	{name: "bits unconstrained", data: []byte{0xa0}, bitLen: 3, hex: "8003a0"},
	// 17.8 aligns every size that is not fixed, also for ub <= 2.
	{name: "octets 0..2", octets: true, data: []byte{0xab}, lb: 0, ub: 2, constrained: true, hex: "a0ab"},
	{name: "octets 0..2 empty", octets: true, trail: true, data: []byte{}, lb: 0, ub: 2, constrained: true, hex: "20"},
	{name: "octets fixed 2", octets: true, data: []byte{0xab, 0xcd}, lb: 2, ub: 2, constrained: true, hex: "d5e680"},
	{name: "octets fixed 3", octets: true, data: []byte{0xab, 0xcd, 0xef}, lb: 3, ub: 3, constrained: true, hex: "80abcdef"},
	{name: "octets 1..8", octets: true, data: []byte{0xab}, lb: 1, ub: 8, constrained: true, hex: "80ab"},
}

func (vector alignedStringVector) encode(bb *BitBuffer) error {
	if !vector.trail {
		if err := EncodeBoolean(bb, true); err != nil {
			return err
		}
	}
	var err error
	if vector.octets {
		err = EncodeOctetStringAlignedExt(bb, vector.data, vector.lb, vector.ub, vector.constrained, vector.extensible)
	} else {
		err = EncodeBitStringAlignedExt(bb, vector.data, vector.bitLen, vector.lb, vector.ub, vector.constrained, vector.extensible)
	}
	if err != nil || !vector.trail {
		return err
	}
	return EncodeBoolean(bb, true)
}

func TestAlignedBitAndOctetStringVectors(t *testing.T) {
	for _, vector := range alignedStringVectors {
		t.Run(vector.name, func(t *testing.T) {
			want, err := hex.DecodeString(vector.hex)
			if err != nil {
				t.Fatal(err)
			}
			bb := NewBitBuffer()
			if err := vector.encode(bb); err != nil {
				t.Fatal(err)
			}
			if got := bb.CompleteBytes(); !bytes.Equal(got, want) {
				t.Fatalf("encode = %x, want %x", got, want)
			}
			reader := NewBitBufferFromBytes(want)
			if !vector.trail {
				if lead, err := DecodeBoolean(reader); err != nil || !lead {
					t.Fatalf("leading BOOLEAN = %v, %v", lead, err)
				}
			}
			if vector.octets {
				got, err := DecodeOctetStringAlignedExt(reader, vector.lb, vector.ub, vector.constrained, vector.extensible)
				if err != nil || !bytes.Equal(got, vector.data) {
					t.Fatalf("decode = %x, %v; want %x", got, err, vector.data)
				}
			} else {
				got, bitLen, err := DecodeBitStringAlignedExt(reader, vector.lb, vector.ub, vector.constrained, vector.extensible)
				if err != nil || bitLen != vector.bitLen || !bytes.Equal(got, vector.data) {
					t.Fatalf("decode = %x/%d, %v; want %x/%d", got, bitLen, err, vector.data, vector.bitLen)
				}
			}
			if vector.trail {
				if trail, err := DecodeBoolean(reader); err != nil || !trail {
					t.Fatalf("trailing BOOLEAN = %v, %v", trail, err)
				}
			}
			if err := ValidateFinalPadding(reader); err != nil {
				t.Fatalf("decode left %d bits: %v", reader.BitsRemaining(), err)
			}
		})
	}
}

// X.691 (02/2021) 16.6 and 17.3 mark only a length outside the root as an
// extension; a root length in extension form is rejected in both variants.
func TestBitAndOctetStringRejectRootLengthInExtensionForm(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		run  func(*BitBuffer) error
	}{
		{"aper bits", "800030", func(bb *BitBuffer) error { _, _, err := DecodeBitStringAlignedExt(bb, 0, 2, true, true); return err }},
		{"aper octets", "8001ab", func(bb *BitBuffer) error { _, err := DecodeOctetStringAlignedExt(bb, 0, 2, true, true); return err }},
		{"uper bits", "80c0", func(bb *BitBuffer) error { _, _, err := DecodeBitStringExt(bb, 1, 8, true, true); return err }},
		{"uper octets", "80d580", func(bb *BitBuffer) error { _, err := DecodeOctetStringExt(bb, 1, 8, true, true); return err }},
	} {
		wire, _ := hex.DecodeString(tc.wire)
		if err := tc.run(NewBitBufferFromBytes(wire)); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s %s: error %v, want ErrInvalidValue", tc.name, tc.wire, err)
		}
	}
}

// FuzzAlignedBitAndOctetStringRoundTrip checks that every accepted ALIGNED
// BIT STRING or OCTET STRING re-encodes to exactly the bits it consumed,
// alignment padding included, for each size form of clauses 16 and 17.
func FuzzAlignedBitAndOctetStringRoundTrip(f *testing.F) {
	for _, vector := range alignedStringVectors {
		wire, _ := hex.DecodeString(vector.hex)
		f.Add(wire, vector.octets, uint8(0))
	}
	// A root length in extension form, found by this target.
	f.Add([]byte{0x80, 0x00, 0x30}, false, uint8(0x88))
	f.Fuzz(func(t *testing.T, wire []byte, octets bool, selector uint8) {
		sizes := [][3]int64{{0, 0, 0}, {0, 8, 1}, {1, 16, 1}, {1, 17, 1}, {16, 16, 1}, {17, 17, 1}, {0, 2, 1}, {2, 2, 1}, {3, 3, 1}, {1, 8, 1}}
		size := sizes[int(selector)%len(sizes)]
		vector := alignedStringVector{octets: octets, trail: true, lb: size[0], ub: size[1], constrained: size[2] == 1, extensible: selector&0x80 != 0}
		reader := NewBitBufferFromBytes(wire)
		var err error
		if octets {
			vector.data, err = DecodeOctetStringAlignedExt(reader, vector.lb, vector.ub, vector.constrained, vector.extensible)
		} else {
			vector.data, vector.bitLen, err = DecodeBitStringAlignedExt(reader, vector.lb, vector.ub, vector.constrained, vector.extensible)
		}
		if err != nil {
			return
		}
		if _, err := DecodeBoolean(reader); err != nil {
			return
		}
		consumed := reader.BitPos()
		bb := NewBitBuffer()
		if err := vector.encode(bb); err != nil {
			t.Fatalf("re-encode %x/%d: %v", vector.data, vector.bitLen, err)
		}
		// The trailing BOOLEAN was decoded as whatever bit was present.
		if bb.BitsWritten() != consumed {
			t.Fatalf("re-encode wrote %d bits, decode consumed %d", bb.BitsWritten(), consumed)
		}
		if !prefixBitsEqual(bb.Bytes(), wire, consumed-1) {
			t.Fatalf("re-encode %x differs from the %d consumed bits of %x", bb.Bytes(), consumed, wire)
		}
	})
}
