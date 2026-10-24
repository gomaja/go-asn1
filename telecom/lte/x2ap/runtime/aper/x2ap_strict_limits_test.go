// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/x2ap_strict_limits_test.go; SHA-256 1b3397da438f47dbb73c347ba7b9530de42cfdecafb1508ed164a7d95391c5f2.
package aper

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// X.691 (02/2021) §§30.5.3–30.5.4(a) restrict VisibleString to 32..126.
func TestX2APVisibleStringStrictAlphabetLocation(t *testing.T) {
	for _, code := range []byte{0, 31, 127, 128, 255} {
		bb := NewBitBufferFromBytes([]byte{1, code})
		_, err := DecodeVisibleStringAligned(bb)
		var located *DecodeError
		if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause != "§30.5.3" || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (BitSpan{Start: 8, End: 16}) {
			t.Fatalf("code=%d err=%v location=%+v", code, err, located)
		}
		if err := EncodeVisibleStringAligned(NewBitBuffer(), string([]byte{code})); !errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("code=%d encode=%v", code, err)
		}
	}
	for _, code := range []byte{32, 126} {
		if value, err := DecodeVisibleStringAligned(NewBitBufferFromBytes([]byte{1, code})); err != nil || value != string([]byte{code}) {
			t.Fatalf("code=%d value=%q err=%v", code, value, err)
		}
	}
}

func TestX2APStringBudgetsAndGrowth(t *testing.T) {
	var previous DecodeUsage
	for _, size := range []int{16384, 32768, 65536} {
		value := strings.Repeat("A", size)
		writer := NewBitBuffer()
		if err := EncodeVisibleStringAligned(writer, value); err != nil {
			t.Fatal(err)
		}
		state := ApplyDecodeOptions()
		reader := NewBitBufferFromBytes(writer.CompleteBytes())
		if err := reader.SetDecodeOptionsAligned(state); err != nil {
			t.Fatal(err)
		}
		if got, err := DecodeVisibleStringAligned(reader); err != nil || got != value {
			t.Fatalf("decode length=%d err=%v", len(got), err)
		}
		usage := state.Usage()
		if previous.Work != 0 && (usage.Work > previous.Work*3 || usage.AllocatedBytes > previous.AllocatedBytes*3) {
			t.Fatalf("nonlinear %d %+v previous %+v", size, usage, previous)
		}
		previous = usage
		limited := ApplyDecodeOptions(WithLimits(Limits{MaxAllocatedBytes: 1024 + uint64(size) - 1}))
		reader = NewBitBufferFromBytes(writer.CompleteBytes())
		if err := reader.SetDecodeOptionsAligned(limited); err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeVisibleStringAligned(reader); !errors.Is(err, ErrLimit) {
			t.Fatalf("string allocation not charged: %v", err)
		}
		budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxWork: 1024 + uint64(size) - 1}))
		if err != nil {
			t.Fatal(err)
		}
		bounded := NewBudgetBuffer(budget)
		if err := EncodeVisibleStringAligned(bounded, value); !errors.Is(err, ErrLimit) || len(bounded.Bytes()) != 0 {
			t.Fatalf("string scanned before budget check: %v", err)
		}
	}
}

// X.691 §§13.1–13.2 select the root/value set and §11.4.6 the extension.
func TestX2APAdditionalIntegerGuardsAreLocated(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
		run  func(*BitBuffer) error
	}{
		{"unsigned unused", []byte{0xc0}, func(bb *BitBuffer) error { _, err := DecodeIntegerUint64Aligned(bb, 0, 2, false); return err }},
		{"unsigned nonminimal", []byte{0x40, 0, 1}, func(bb *BitBuffer) error { _, err := DecodeIntegerUint64Aligned(bb, 0, 65536, false); return err }},
		{"unsigned extension inside root", []byte{0x80, 1, 1}, func(bb *BitBuffer) error { _, err := DecodeIntegerUint64Aligned(bb, 0, 2, true); return err }},
		{"value set gap", []byte{0x80, 0x22}, func(bb *BitBuffer) error {
			_, err := DecodeIntegerValueSetBigAligned(bb, []IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}}, false)
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.run(NewBitBufferFromBytes(test.wire))
			var located *DecodeError
			if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || located.Rule.Clause == "" || !located.Location.HasWireLocation {
				t.Fatalf("err=%v location=%+v", err, located)
			}
		})
	}
}

func TestX2APFieldSnapshotChargesCopiesBeforeAllocation(t *testing.T) {
	state := ApplyDecodeOptions(WithLimits(Limits{MaxAllocatedBytes: 1025}))
	reader := NewBitBufferFromBytes([]byte{1, 2})
	if err := reader.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadBits(16); err != nil {
		t.Fatal(err)
	}
	if form, err := CaptureFieldReceivedForm(reader, 0, "field"); !errors.Is(err, ErrLimit) || form.Present() {
		t.Fatalf("snapshot escaped budget: %+v %v", form, err)
	}
}

func TestX2APUnsignedEncodeReservesBeforeWriting(t *testing.T) {
	budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: 1025}))
	if err != nil {
		t.Fatal(err)
	}
	writer := NewBudgetBuffer(budget)
	if err := EncodeIntegerUint64Aligned(writer, 1, 0, ^uint64(0), false); !errors.Is(err, ErrLimit) || !bytes.Equal(writer.Bytes(), nil) {
		t.Fatalf("unsigned scratch escaped budget: %v", err)
	}
}
