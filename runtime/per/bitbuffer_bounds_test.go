package per

import (
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestBitBufferFromBitsBounds(t *testing.T) {
	for _, tc := range []struct {
		data  []byte
		bits  int
		valid bool
	}{
		{[]byte{0x80}, 1, true},
		{[]byte{0x80}, 0, false},
		{[]byte{0x81}, 1, false},
		{[]byte{0x80}, 9, false},
		{[]byte{0x80}, -1, false},
	} {
		bb, err := NewBitBufferFromBits(tc.data, tc.bits)
		if (err == nil) != tc.valid {
			t.Fatalf("bits %d data %x: err = %v", tc.bits, tc.data, err)
		}
		if err != nil {
			continue
		}
		if got, err := bb.ReadBit(); err != nil || got != 1 {
			t.Fatalf("first bit = %d, %v", got, err)
		}
		if _, err := bb.ReadBit(); err == nil {
			t.Fatal("read beyond declared bit length succeeded")
		}
	}
}

func TestAlignToOctetWriteReturnsWriteBitFailure(t *testing.T) {
	bb := NewBitBuffer()
	bb.bitPos = math.MaxInt
	if err := bb.AlignToOctetWrite(); err == nil {
		t.Fatal("alignment hid the bit-position overflow")
	}
	if bb.bitPos != math.MaxInt || len(bb.data) != 0 {
		t.Fatalf("failed alignment changed buffer: position=%d bytes=%d", bb.bitPos, len(bb.data))
	}
}

func TestAlignedEncodersPropagateAlignmentFailure(t *testing.T) {
	tests := []struct {
		name   string
		encode func(*BitBuffer) error
	}{
		{"length", func(bb *BitBuffer) error { return EncodeUnconstrainedLengthAligned(bb, 0) }},
		{"fragment", func(bb *BitBuffer) error {
			return EncodeLengthFragments(bb, 0, true, func(int64, int64) error { return nil })
		}},
		{"small integer", func(bb *BitBuffer) error { return EncodeConstrainedWholeNumberAligned(bb, 0, 0, 255) }},
		{"big integer", func(bb *BitBuffer) error {
			return encodeConstrainedBig(bb, big.NewInt(0), big.NewInt(0), big.NewInt(255), true)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bb := NewBitBuffer()
			bb.bitPos = math.MaxInt
			if err := tc.encode(bb); err == nil {
				t.Fatal("encoder hid alignment failure")
			}
		})
	}
}

func TestAlignedLengthReturnsAlignmentErrorBeforeLengthError(t *testing.T) {
	bb := NewBitBuffer()
	bb.bitPos = math.MaxInt
	err := EncodeUnconstrainedLengthAligned(bb, -1)
	if err == nil || !strings.Contains(err.Error(), "PER bit position exceeds int") {
		t.Fatalf("error = %v, want alignment WriteBit error before negative length", err)
	}
	if bb.bitPos != math.MaxInt || len(bb.data) != 0 {
		t.Fatalf("failed alignment changed buffer: position=%d bytes=%d", bb.bitPos, len(bb.data))
	}
}
