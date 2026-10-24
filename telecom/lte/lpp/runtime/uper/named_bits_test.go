// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/named_bits_test.go; SHA-256 3ab351e3fd0072707d31e778a27dd1b88c3ca503a0976d96e75ac35118ec7795.
package uper

import (
	"encoding/hex"
	"errors"
	"testing"
)

// X.691 (02/2021) 16.2 and 16.3 give a value of a BIT STRING type with a
// NamedBitList its length: no trailing 0 bits, then 0 bits up to the lower
// bound. An extensible root that can carry the value is used before the
// extension form (16.6).
func TestNamedBitLength(t *testing.T) {
	for _, tc := range []struct {
		name        string
		data        string
		bitLen      int
		lb, ub      int64
		constrained bool
		extensible  bool
		want        int
		err         error
	}{
		{"unconstrained '010'B", "40", 3, 0, 0, false, false, 2, nil},
		{"unconstrained '000'B", "00", 3, 0, 0, false, false, 0, nil},
		{"unconstrained ''B", "", 0, 0, 0, false, false, 0, nil},
		{"unconstrained '1'B", "80", 1, 0, 0, false, false, 1, nil},
		{"(0..8) '010'B", "40", 3, 0, 8, true, false, 2, nil},
		{"(0..8) '01000000'B", "40", 8, 0, 8, true, false, 2, nil},
		{"(2..4) '1'B", "80", 1, 2, 4, true, false, 2, nil},
		{"(2..4) ''B", "", 0, 2, 4, true, false, 2, nil},
		{"(2..4) '0001'B", "10", 4, 2, 4, true, false, 4, nil},
		{"(2..4) '100000'B", "80", 6, 2, 4, true, false, 2, nil},
		{"(2..4) '000001'B", "04", 6, 2, 4, true, false, 0, ErrConstraintViolation},
		{"(2..4, ...) '1'B", "80", 1, 2, 4, true, true, 2, nil},
		{"(2..4, ...) '000001'B", "04", 6, 2, 4, true, true, 6, nil},
		{"(2..4, ...) '0000010'B", "04", 7, 2, 4, true, true, 6, nil},
		{"(8) '01'B", "40", 2, 8, 8, true, false, 8, nil},
		{"(8) '0100000000'B", "4000", 10, 8, 8, true, false, 8, nil},
		{"(8) '000000001'B", "0080", 9, 8, 8, true, false, 0, ErrConstraintViolation},
		{"short octets", "40", 9, 0, 0, false, false, 0, ErrInvalidValue},
		{"negative length", "40", -1, 0, 0, false, false, 0, ErrInvalidValue},
		{"invalid bounds", "40", 3, 4, 2, true, false, 0, ErrInvalidValue},
	} {
		data, _ := hex.DecodeString(tc.data)
		got, err := namedBitLength(data, tc.bitLen, tc.lb, tc.ub, tc.constrained, tc.extensible)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: error %v, want %v", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %d, %v, want %d", tc.name, got, err, tc.want)
		}
		if minimal := NamedBitStringMinimal(data, tc.bitLen, tc.lb, tc.ub, tc.constrained, tc.extensible); minimal != (got == tc.bitLen) {
			t.Errorf("%s: minimal %v, want %v", tc.name, minimal, got == tc.bitLen)
		}
	}
}

func TestLPPNamedBitReplayKeepsReceivedLength(t *testing.T) {
	for _, tc := range []struct {
		keep bool
		want int
	}{{true, 3}, {false, 2}} {
		bb := NewBitBuffer()
		if err := EncodeNamedBitString(bb, []byte{0x40}, 3, 0, 8, true, false, tc.keep); err != nil {
			t.Fatal(err)
		}
		_, length, err := DecodeBitStringExt(NewBitBufferFromBytes(bb.CompleteBytes()), 0, 8, true, false)
		if err != nil || length != tc.want {
			t.Fatalf("keep=%v length=%d, err=%v, want %d", tc.keep, length, err, tc.want)
		}
	}
}

// The example of go-asn1#98, Flags ::= BIT STRING { a(0), b(1), c(2) }
// (SIZE (0..8)): '010'B and '01'B are one abstract value (X.680 (02/2021)
// 22.7), encoded with length 2 in both variants. A decoded '010'B kept as
// received is encoded with its own length.

// 0 bits added up to the lower bound are 0 even where the octets of the
// value hold other bits beyond its length.

// FuzzNamedBitStringRoundTrip checks the rule of X.691 (02/2021) 16.2 and
// 16.3 and its replay exception: every accepted BIT STRING re-encodes to the
// bits it consumed when it is kept if and only if it is not minimal, and its
// new encoding decodes as a minimal value with the same 1 bits.

// A kept BIT STRING is replayed only while the value is exactly the received
// one: same length, same bits, whatever lies beyond the length. The record
// holds a copy, so an edit of the decoded octets in place is a change.
func TestKeptBitsKeepsOnlyTheReceivedValue(t *testing.T) {
	received := []byte{0x40}
	kept := KeepBitString(received, 3) // '010'B
	received[0] = 0xc0                 // edited in place after decoding
	for _, tc := range []struct {
		data   []byte
		bitLen int
		want   bool
	}{
		{[]byte{0x40}, 3, true},
		{[]byte{0x5f}, 3, true}, // bits beyond the length do not count
		{[]byte{0xc0}, 3, false},
		{[]byte{0x40}, 2, false},
		{[]byte{0x40}, 4, false},
		{nil, 3, false},
	} {
		if got := kept.Keeps(tc.data, tc.bitLen); got != tc.want {
			t.Errorf("Keeps(%x, %d) = %v, want %v", tc.data, tc.bitLen, got, tc.want)
		}
	}
	whole := KeepBitString([]byte{0x12, 0x34, 0xff}, 16)
	if !whole.Keeps([]byte{0x12, 0x34}, 16) || whole.Keeps([]byte{0x12, 0x35}, 16) || whole.Keeps([]byte{0x12}, 16) {
		t.Error("16-bit record")
	}
	partial := KeepBitString([]byte{0x12, 0x30}, 12)
	if !partial.Keeps([]byte{0x12, 0x3f}, 12) || partial.Keeps([]byte{0x12, 0x20}, 12) || partial.Keeps([]byte{0x12}, 12) {
		t.Error("12-bit record")
	}
	if !KeepBitString([]byte{0x40}, 9).IsZero() || !KeepBitString(nil, -1).IsZero() {
		t.Error("a record of an impossible value")
	}
	if (KeptBits{}).Keeps([]byte{0x40}, 3) || kept.List(1).Keeps([]byte{0x40}, 3) {
		t.Error("an empty record keeps")
	}
}

// A list record keeps an element's length only while the list has its
// received length, element by element, across list fragments.
func TestKeptBitsList(t *testing.T) {
	element := KeepBitString([]byte{0x80}, 3) // '100'B
	elements := KeepAt(KeepAt(nil, 1, KeptBits{}), 3, element)
	if len(elements) != 4 || !elements[1].IsZero() || elements[3].IsZero() {
		t.Fatalf("KeepAt: %d records", len(elements))
	}
	list := KeptList(5, elements)
	if list.IsZero() || !KeptList(5, nil).IsZero() || !KeptList(2, elements).IsZero() {
		t.Fatal("KeptList")
	}
	if !list.List(5).ElementAt(2, 1).Keeps([]byte{0x80}, 3) || !list.List(5).ElementAt(0, 3).Keeps([]byte{0x80}, 3) {
		t.Error("element 3 not kept")
	}
	for _, at := range []struct {
		offset int64
		index  int
	}{{0, 0}, {0, 4}, {4, 0}, {-1, 4}, {2, -1}, {1 << 40, 0}} {
		if !list.List(5).ElementAt(at.offset, at.index).IsZero() {
			t.Errorf("ElementAt(%d, %d) is not empty", at.offset, at.index)
		}
	}
	if !list.List(4).ElementAt(0, 3).IsZero() || !element.List(1).IsZero() || !element.ElementAt(0, 0).IsZero() {
		t.Error("a changed list keeps a length")
	}
	if got := testing.AllocsPerRun(100, func() { keptListSink = KeepAt(nil, 2, KeptBits{}) }); got != 0 {
		t.Errorf("KeepAt of an empty record allocates %v", got)
	}
}

var keptListSink []KeptBits

// Decision (go-asn1#98): with an extensible SIZE (2..4, ...), a value whose
// 1 bits fit the root is padded with 0 bits to the root's lower bound and
// sent in the root, never in extension form with a shorter length. X.680
// (02/2021) 22.7 makes '1'B and '10'B one abstract value, so the root
// carries it (X.691 (02/2021) 16.3, 10.3.10), and a root value in extension
// form is what 13.1, 16.6 and 17.3 reserve for values outside the root.

// '1'B: padded to 2 bits, root
// ''B: two 0 bits, root
// '0001'B: root
// '000001'B: needs 6 bits, extension
// '00000100'B: trimmed to 6, extension
