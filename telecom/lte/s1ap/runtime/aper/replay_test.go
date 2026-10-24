// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay_test.go; SHA-256 e1cddd2370ad76425a3755ee4895b2a34885308a0912daa83be04afe4ebc40b6.
package aper

import (
	"math/big"
	"testing"
)

func TestBitStringSnapshotsUseOnlyDeclaredBits(t *testing.T) {
	var root Snapshot
	capture := NewSemanticCapture(256)
	f := capture.Begin()
	capture.BitString([]byte{0xa0}, 4)
	capture.End(f, &root, false)
	for _, test := range []struct {
		data []byte
		bits int
		want bool
	}{
		{[]byte{0xaf}, 4, true},
		{[]byte{0xaf, 0xff}, 4, true},
		{[]byte{0xb0}, 4, false},
		{[]byte{0xa0}, 5, false},
		{nil, 4, false},
		{nil, -1, false},
	} {
		compare := NewSemanticComparison(root)
		f := compare.Begin()
		compare.BitString(test.data, test.bits)
		compare.End(f, root, false)
		plan := compare.Plan()
		if got := plan.Unchanged(root); got != test.want {
			t.Errorf("bits %x/%d: unchanged=%v, want %v", test.data, test.bits, got, test.want)
		}
	}
}

func TestSemanticSnapshotsAreExactAndOwned(t *testing.T) {
	var root, child Snapshot
	data := []byte{1, 2, 3}
	integer := big.NewInt(1)
	capture := func(s *SemanticCapture) {
		f := s.Begin()
		s.Uint(42)
		s.Int(-42)
		c := s.Begin()
		s.Bytes(data)
		s.BigInt(integer)
		s.End(c, &child, false)
		s.Uint(99)
		s.End(f, &root, false)
	}
	s := NewSemanticCapture(1)
	capture(&s)
	check := func(want bool) {
		t.Helper()
		s := NewSemanticComparison(root)
		f := s.Begin()
		s.Uint(42)
		s.Int(-42)
		c := s.Begin()
		s.Bytes(data)
		s.BigInt(integer)
		s.End(c, child, false)
		s.Uint(99)
		s.End(f, root, false)
		p := s.Plan()
		if p.Unchanged(root) != want {
			t.Fatalf("unchanged=%v want %v", p.Unchanged(root), want)
		}
	}
	check(true)
	data[0] = 9
	check(false)
	data[0] = 1
	check(true)
	integer.Lsh(integer, 129)
	check(false)
	integer.SetInt64(1)
	check(true)
	data = append(data, 4)
	check(false)
	data = data[:3]
	check(true)
}

func TestSemanticSpanSnapshotsAcrossRepresentations(t *testing.T) {
	original, options := ownTestDecodeInput([]byte{1, 2, 3}, decodeSettings{})
	image := OriginalWire(original)
	opaque := OpaqueOpenType{image: image}
	choice := ChoiceExtension{index: 7, image: image}
	var root Snapshot
	capture := testSemanticCaptureFor(options)
	f := capture.Begin()
	capture.String("source")
	capture.Opaque(opaque)
	capture.ChoiceExtension(&choice)
	capture.ExtensionData([][]byte{nil}, []WireSpan{image})
	capture.End(f, &root, false)
	if !root.Present() || (Snapshot{}).Present() {
		t.Fatal("snapshot presence differs")
	}
	compare := func(text string, content OpaqueOpenType, alternative *ChoiceExtension, data [][]byte, spans []WireSpan) bool {
		c := NewSemanticComparison(root)
		f := c.Begin()
		c.String(text)
		c.Opaque(content)
		c.ChoiceExtension(alternative)
		c.ExtensionData(data, spans)
		c.End(f, root, false)
		p := c.Plan()
		return p.Unchanged(root)
	}
	if !compare("source", NewOpaqueOpenType([]byte{1, 2, 3}), &choice, [][]byte{{1, 2, 3}}, nil) {
		t.Fatal("equal contents depend on their storage representation")
	}
	if compare("edited", opaque, &choice, [][]byte{nil}, []WireSpan{image}) {
		t.Fatal("string edit was missed")
	}
	if compare("source", NewOpaqueOpenType([]byte{9, 2, 3}), &choice, [][]byte{nil}, []WireSpan{image}) {
		t.Fatal("opaque replacement was missed")
	}
	changed := choice
	changed.index = 8
	if compare("source", opaque, &changed, [][]byte{nil}, []WireSpan{image}) {
		t.Fatal("choice extension edit was missed")
	}
	if compare("source", opaque, &choice, [][]byte{{1, 2, 4}}, nil) {
		t.Fatal("extension setter edit was missed")
	}
	prepared := ExtensionContents([][]byte{nil}, []WireSpan{image})
	prepared[0][0] = 9
	if original[0] != 1 {
		t.Fatal("prepared extension bytes alias original")
	}
}

func TestLargePlanAllocatesDecisionsOnlyAfterChange(t *testing.T) {
	var root Snapshot
	children := make([]Snapshot, 600)
	s := NewSemanticCapture(16384)
	f := s.Begin()
	for i := range children {
		child := s.Begin()
		s.Uint(uint64(i))
		s.End(child, &children[i], false)
	}
	s.End(f, &root, false)
	compare := func(changed bool) ReplayPlan {
		c := NewSemanticComparison(root)
		f := c.Begin()
		for i := range children {
			child := c.Begin()
			value := uint64(i)
			if changed && i == 599 {
				value++
			}
			c.Uint(value)
			c.End(child, children[i], false)
		}
		c.End(f, root, false)
		return c.Plan()
	}
	if got := testing.AllocsPerRun(20, func() {
		p := compare(false)
		if !p.Unchanged(root) || len(p.extra) != 0 {
			panic("unchanged plan allocated overflow")
		}
	}); got != 0 {
		t.Fatalf("unchanged large plan allocates %.0f", got)
	}
	p := compare(true)
	if p.Unchanged(root) || p.Unchanged(children[599]) || len(p.extra) == 0 || !p.Unchanged(children[0]) {
		t.Fatal("sparse changed decisions differ")
	}
}
func TestCopiedNodeCannotClearAnEarlierChangedOccurrence(t *testing.T) {
	var root, a, b Snapshot
	s := NewSemanticCapture(256)
	f := s.Begin()
	ca := s.Begin()
	s.Uint(1)
	s.End(ca, &a, false)
	cb := s.Begin()
	s.Uint(2)
	s.End(cb, &b, false)
	s.End(f, &root, false)
	c := NewSemanticComparison(root)
	f = c.Begin()
	ca = c.Begin()
	c.Uint(3)
	c.End(ca, b, false)
	cb = c.Begin()
	c.Uint(2)
	c.End(cb, b, false)
	c.End(f, root, false)
	p := c.Plan()
	if p.Unchanged(root) || p.Unchanged(b) {
		t.Fatal("unchanged copied occurrence hid an earlier edit")
	}
}
