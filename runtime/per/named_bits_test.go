package per

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gomaja/go-asn1/runtime"
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

// The example of go-asn1#98, Flags ::= BIT STRING { a(0), b(1), c(2) }
// (SIZE (0..8)): '010'B and '01'B are one abstract value (X.680 (02/2021)
// 22.7), encoded with length 2 in both variants. A decoded '010'B kept as
// received is encoded with its own length.
func TestEncodeNamedBitString(t *testing.T) {
	for _, tc := range []struct {
		name    string
		aligned bool
		data    string
		bitLen  int
		keep    bool
		want    string
	}{
		{"uper '010'B", false, "40", 3, false, "24"},
		{"uper '01'B", false, "40", 2, false, "24"},
		{"uper kept '010'B", false, "40", 3, true, "34"},
		{"uper '0'B", false, "00", 1, false, "00"},
		{"aper '010'B", true, "40", 3, false, "2040"},
		{"aper kept '010'B", true, "40", 3, true, "3040"},
	} {
		data, _ := hex.DecodeString(tc.data)
		bb := NewBitBuffer()
		encode := EncodeNamedBitString
		if tc.aligned {
			encode = EncodeNamedBitStringAligned
		}
		if err := encode(bb, data, tc.bitLen, 0, 8, true, false, tc.keep); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := hex.EncodeToString(bb.CompleteBytes()); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
	// 0 bits added up to the lower bound are 0 even where the octets of the
	// value hold other bits beyond its length.
	bb := NewBitBuffer()
	if err := EncodeNamedBitString(bb, []byte{0xbf}, 2, 4, 4, true, false, false); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(bb.CompleteBytes()); got != "80" {
		t.Errorf("'10'B in SIZE (4) with stray bits: %s, want 80", got)
	}
	if err := EncodeNamedBitString(NewBitBuffer(), []byte{0x40}, 9, 0, 0, false, false, false); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("short octets: %v, want ErrInvalidValue", err)
	}
}

func namedBitsDecode(bb *BitBuffer, lb, ub int64, constrained, extensible, aligned bool) ([]byte, int, error) {
	if aligned {
		return DecodeBitStringAlignedExt(bb, lb, ub, constrained, extensible)
	}
	return DecodeBitStringExt(bb, lb, ub, constrained, extensible)
}

var namedBitsSizes = [][4]int64{{0, 0, 0, 0}, {0, 8, 1, 0}, {2, 4, 1, 0}, {2, 4, 1, 1}, {8, 8, 1, 0}, {1, 16, 1, 1}, {0, 2, 1, 0}, {20, 20, 1, 0}}

// FuzzNamedBitStringRoundTrip checks the rule of X.691 (02/2021) 16.2 and
// 16.3 and its replay exception: every accepted BIT STRING re-encodes to the
// bits it consumed when it is kept if and only if it is not minimal, and its
// new encoding decodes as a minimal value with the same 1 bits.
func FuzzNamedBitStringRoundTrip(f *testing.F) {
	f.Add([]byte{0x34}, uint8(1))
	f.Add([]byte{0x24}, uint8(1))
	f.Add([]byte{0x30, 0x40}, uint8(0x81))
	f.Add([]byte{0x03, 0x00}, uint8(0))
	f.Fuzz(func(t *testing.T, wire []byte, selector uint8) {
		size := namedBitsSizes[int(selector&0x7f)%len(namedBitsSizes)]
		aligned := selector&0x80 != 0
		lb, ub, constrained, extensible := size[0], size[1], size[2] == 1, size[3] == 1
		reader := NewBitBufferFromBytes(wire)
		data, bitLen, err := namedBitsDecode(reader, lb, ub, constrained, extensible, aligned)
		if err != nil {
			return
		}
		consumed := reader.BitPos()
		minimal := NamedBitStringMinimal(data, bitLen, lb, ub, constrained, extensible)
		encode := EncodeNamedBitString
		if aligned {
			encode = EncodeNamedBitStringAligned
		}
		kept := NewBitBuffer()
		if err := encode(kept, data, bitLen, lb, ub, constrained, extensible, !minimal); err != nil {
			t.Fatalf("re-encoding %x/%d: %v", data, bitLen, err)
		}
		if kept.BitsWritten() != consumed || !prefixBitsEqual(kept.Bytes(), wire, consumed) {
			t.Fatalf("%x/%d (minimal %v) re-encoded %x/%d, consumed %d bits of %x", data, bitLen, minimal, kept.Bytes(), kept.BitsWritten(), consumed, wire)
		}
		fresh := NewBitBuffer()
		if err := encode(fresh, data, bitLen, lb, ub, constrained, extensible, false); err != nil {
			t.Fatalf("fresh encoding %x/%d: %v", data, bitLen, err)
		}
		if minimal != (fresh.BitsWritten() == consumed && bytes.Equal(fresh.Bytes(), kept.Bytes())) {
			t.Fatalf("%x/%d: minimal %v, fresh %x/%d", data, bitLen, minimal, fresh.Bytes(), fresh.BitsWritten())
		}
		again, againLen, err := namedBitsDecode(NewBitBufferFromBytes(fresh.Bytes()), lb, ub, constrained, extensible, aligned)
		if err != nil || !NamedBitStringMinimal(again, againLen, lb, ub, constrained, extensible) {
			t.Fatalf("fresh %x of %x/%d decodes as %x/%d, %v, not minimal", fresh.Bytes(), data, bitLen, again, againLen, err)
		}
		if !(runtime.BitString{Bytes: again, BitLength: againLen}).EqualBits(string(data), bitLen, true) {
			t.Fatalf("fresh %x/%d is another value than %x/%d", again, againLen, data, bitLen)
		}
	})
}

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
	for _, at := range [][2]int{{0, 0}, {0, 4}, {4, 0}, {-1, 4}, {2, -1}, {1 << 40, 0}} {
		if !list.List(5).ElementAt(int64(at[0]), at[1]).IsZero() && at != [2]int{0, 3} {
			t.Errorf("ElementAt(%d, %d) is not empty", at[0], at[1])
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
func TestExtensibleNamedBitsPadIntoTheRoot(t *testing.T) {
	for _, aligned := range []bool{false, true} {
		for _, tc := range []struct {
			data      []byte
			bitLen    int
			extension bool
			length    int
		}{
			{[]byte{0x80}, 1, false, 2}, // '1'B: padded to 2 bits, root
			{nil, 0, false, 2},          // ''B: two 0 bits, root
			{[]byte{0x10}, 4, false, 4}, // '0001'B: root
			{[]byte{0x04}, 6, true, 6},  // '000001'B: needs 6 bits, extension
			{[]byte{0x04}, 8, true, 6},  // '00000100'B: trimmed to 6, extension
		} {
			bb := NewBitBuffer()
			encode := EncodeNamedBitString
			if aligned {
				encode = EncodeNamedBitStringAligned
			}
			if err := encode(bb, tc.data, tc.bitLen, 2, 4, true, true, false); err != nil {
				t.Fatalf("aligned %v %x/%d: %v", aligned, tc.data, tc.bitLen, err)
			}
			wire := bb.CompleteBytes()
			if extension := wire[0]&0x80 != 0; extension != tc.extension {
				t.Errorf("aligned %v %x/%d: extension bit %v, want %v", aligned, tc.data, tc.bitLen, extension, tc.extension)
			}
			_, length, err := namedBitsDecode(NewBitBufferFromBytes(wire), 2, 4, true, true, aligned)
			if err != nil || length != tc.length {
				t.Errorf("aligned %v %x/%d: sent with length %d, %v, want %d", aligned, tc.data, tc.bitLen, length, err, tc.length)
			}
		}
	}
}
