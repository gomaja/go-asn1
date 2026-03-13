package per

import (
	"testing"
)

func TestBitBuffer_WriteBitsReadBits(t *testing.T) {
	bb := NewBitBuffer()
	if err := bb.WriteBits(0b10110, 5); err != nil {
		t.Fatal(err)
	}
	if err := bb.WriteBits(0b1101, 4); err != nil {
		t.Fatal(err)
	}
	// Total: 9 bits = 10110 1101 = 0b10110110 1xxxxxxx
	data := bb.Bytes()
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	if data[0] != 0b10110110 {
		t.Fatalf("byte 0: got %08b, want 10110110", data[0])
	}
	if data[1]&0x80 != 0x80 {
		t.Fatalf("byte 1 high bit: got %08b, want 1xxxxxxx", data[1])
	}

	// Read back.
	rbb := NewBitBufferFromBytes(data)
	v1, err := rbb.ReadBits(5)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != 0b10110 {
		t.Fatalf("read 5 bits: got %05b, want 10110", v1)
	}
	v2, err := rbb.ReadBits(4)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 0b1101 {
		t.Fatalf("read 4 bits: got %04b, want 1101", v2)
	}
}

func TestConstrainedWholeNumber_RoundTrip(t *testing.T) {
	tests := []struct {
		v, lb, ub int64
	}{
		{0, 0, 255},
		{255, 0, 255},
		{100, 0, 255},
		{0, 0, 0},
		{5, 5, 5},
		{-10, -20, 20},
		{0, 0, 65535},
		{12345, 0, 65535},
	}
	for _, tc := range tests {
		bb := NewBitBuffer()
		if err := EncodeConstrainedWholeNumber(bb, tc.v, tc.lb, tc.ub); err != nil {
			t.Fatalf("encode(%d, %d, %d): %v", tc.v, tc.lb, tc.ub, err)
		}
		rbb := NewBitBufferFromBytes(bb.Bytes())
		got, err := DecodeConstrainedWholeNumber(rbb, tc.lb, tc.ub)
		if err != nil {
			t.Fatalf("decode(%d, %d, %d): %v", tc.v, tc.lb, tc.ub, err)
		}
		if got != tc.v {
			t.Fatalf("round-trip(%d, [%d..%d]): got %d", tc.v, tc.lb, tc.ub, got)
		}
	}
}

func TestBoolean_RoundTrip(t *testing.T) {
	for _, v := range []bool{true, false} {
		bb := NewBitBuffer()
		if err := EncodeBoolean(bb, v); err != nil {
			t.Fatal(err)
		}
		rbb := NewBitBufferFromBytes(bb.Bytes())
		got, err := DecodeBoolean(rbb)
		if err != nil {
			t.Fatal(err)
		}
		if got != v {
			t.Fatalf("boolean round-trip: got %v, want %v", got, v)
		}
	}
}

func TestEnumerated_RoundTrip(t *testing.T) {
	tests := []struct {
		v         int64
		rootCount int
		ext       bool
	}{
		{0, 4, false},
		{3, 4, false},
		{0, 4, true},
		{2, 4, true},
	}
	for _, tc := range tests {
		bb := NewBitBuffer()
		if err := EncodeEnumerated(bb, tc.v, tc.rootCount, tc.ext); err != nil {
			t.Fatalf("encode enum %d: %v", tc.v, err)
		}
		rbb := NewBitBufferFromBytes(bb.Bytes())
		got, err := DecodeEnumerated(rbb, tc.rootCount, tc.ext)
		if err != nil {
			t.Fatalf("decode enum %d: %v", tc.v, err)
		}
		if got != tc.v {
			t.Fatalf("enum round-trip: got %d, want %d", got, tc.v)
		}
	}
}

func TestInteger_RoundTrip(t *testing.T) {
	lb := func(v int64) *int64 { return &v }

	tests := []struct {
		name       string
		v          int64
		lb, ub     *int64
		extensible bool
	}{
		{"constrained", 42, lb(0), lb(255), false},
		{"semi-constrained", 100, lb(0), nil, false},
		{"unconstrained", -42, nil, nil, false},
		{"extensible-in-root", 10, lb(0), lb(100), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := EncodeInteger(bb, tc.v, tc.lb, tc.ub, tc.extensible); err != nil {
				t.Fatalf("encode: %v", err)
			}
			rbb := NewBitBufferFromBytes(bb.Bytes())
			got, err := DecodeInteger(rbb, tc.lb, tc.ub, tc.extensible)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got != tc.v {
				t.Fatalf("got %d, want %d", got, tc.v)
			}
		})
	}
}

func TestOctetString_RoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		lb, ub      int64
		constrained bool
	}{
		{"fixed-4", []byte{1, 2, 3, 4}, 4, 4, true},
		{"variable", []byte{0xAB, 0xCD}, 1, 10, true},
		{"unconstrained", []byte{1, 2, 3, 4, 5}, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := EncodeOctetString(bb, tc.data, tc.lb, tc.ub, tc.constrained); err != nil {
				t.Fatal(err)
			}
			rbb := NewBitBufferFromBytes(bb.Bytes())
			got, err := DecodeOctetString(rbb, tc.lb, tc.ub, tc.constrained)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.data) {
				t.Fatalf("length: got %d, want %d", len(got), len(tc.data))
			}
			for i := range got {
				if got[i] != tc.data[i] {
					t.Fatalf("byte %d: got %02x, want %02x", i, got[i], tc.data[i])
				}
			}
		})
	}
}

func TestBitString_RoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		bitLen      int
		lb, ub      int64
		constrained bool
	}{
		{"fixed-8", []byte{0xFF}, 8, 8, 8, true},
		{"fixed-27", []byte{0xFF, 0xAB, 0xCD, 0xE0}, 27, 27, 27, true},
		{"variable", []byte{0xAB, 0xC0}, 12, 1, 32, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			if err := EncodeBitString(bb, tc.data, tc.bitLen, tc.lb, tc.ub, tc.constrained); err != nil {
				t.Fatal(err)
			}
			rbb := NewBitBufferFromBytes(bb.Bytes())
			gotData, gotBitLen, err := DecodeBitString(rbb, tc.lb, tc.ub, tc.constrained)
			if err != nil {
				t.Fatal(err)
			}
			if gotBitLen != tc.bitLen {
				t.Fatalf("bitLen: got %d, want %d", gotBitLen, tc.bitLen)
			}
			// Compare all significant bits, including the partial last byte.
			fullBytes := tc.bitLen / 8
			for i := 0; i < fullBytes; i++ {
				if gotData[i] != tc.data[i] {
					t.Fatalf("byte %d: got %02x, want %02x", i, gotData[i], tc.data[i])
				}
			}
			if remBits := tc.bitLen % 8; remBits > 0 {
				mask := byte(0xFF << (8 - remBits))
				if gotData[fullBytes]&mask != tc.data[fullBytes]&mask {
					t.Fatalf("partial byte %d: got %02x, want %02x (mask %02x)", fullBytes, gotData[fullBytes], tc.data[fullBytes], mask)
				}
			}
		})
	}
}

func TestOpenType_RoundTrip(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	bb := NewBitBuffer()
	if err := EncodeOpenType(bb, data); err != nil {
		t.Fatal(err)
	}
	rbb := NewBitBufferFromBytes(bb.Bytes())
	got, err := DecodeOpenType(rbb)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(data) {
		t.Fatalf("length: got %d, want %d", len(got), len(data))
	}
	for i := range got {
		if got[i] != data[i] {
			t.Fatalf("byte %d: got %02x, want %02x", i, got[i], data[i])
		}
	}
}

func TestChoiceIndex_RoundTrip(t *testing.T) {
	tests := []struct {
		index    int64
		numAlts  int
		ext      bool
		wantExt  bool
	}{
		{0, 4, false, false},
		{3, 4, false, false},
		{0, 4, true, false},
		{2, 4, true, false},
	}
	for _, tc := range tests {
		bb := NewBitBuffer()
		if err := EncodeChoiceIndex(bb, tc.index, tc.numAlts, tc.ext); err != nil {
			t.Fatal(err)
		}
		rbb := NewBitBufferFromBytes(bb.Bytes())
		got, gotExt, err := DecodeChoiceIndex(rbb, tc.numAlts, tc.ext)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.index {
			t.Fatalf("index: got %d, want %d", got, tc.index)
		}
		if gotExt != tc.wantExt {
			t.Fatalf("ext: got %v, want %v", gotExt, tc.wantExt)
		}
	}
}
