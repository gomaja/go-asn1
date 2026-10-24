// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/observation_location_test.go; SHA-256 f29c0234efe055158e5e001745a1ccb91b1b6120f6b757d7558e2cd36a66769e.
package aper

import (
	"errors"
	"testing"
)

// X.691 (02/2021) §23.8 identifies an unknown CHOICE alternative's boundary.
// The report must own its member path before the runtime publishes the record.
func TestChoiceObservationNamesItsMember(t *testing.T) {
	state := ApplyDecodeOptions()
	reader := NewBitBufferFromBytes([]byte{1, 0})
	if err := reader.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	extension, err := DecodeChoiceExtensionAligned(reader, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := extension.ObserveUnknown(reader); err != nil {
		t.Fatal(err)
	}
	report, err := FinishDecode(state, nil)
	if err != nil || len(report.Observations) != 1 || report.Observations[0].Location.Path != "UnknownExtension" {
		t.Fatalf("choice observation=%+v err=%v", report, err)
	}
}

func TestChoiceChildKeepsOriginalSpans(t *testing.T) {
	for _, size := range []int{1, 16385} {
		contents := make([]byte, size)
		contents[size-1] = 0xc0
		writer := NewBitBuffer()
		if err := writer.WriteBytes([]byte{0xaa}); err != nil {
			t.Fatal(err)
		}
		if err := EncodeOpenTypeAligned(writer, contents); err != nil {
			t.Fatal(err)
		}
		wire := writer.CompleteBytes()
		parent := NewBitBufferFromBytes(wire)
		if _, err := parent.ReadBytes(1); err != nil {
			t.Fatal(err)
		}
		extension, err := DecodeChoiceExtensionAligned(parent, 0)
		if err != nil {
			t.Fatal(err)
		}
		child := extension.ChildDecodeBuffer(parent)
		if _, err := child.ReadBytes(size - 1); err != nil {
			t.Fatal(err)
		}
		_, err = DecodeIntegerUint64Aligned(child, 0, 2, false)
		var located *DecodeError
		want := BitSpan{Start: uint64(len(wire)-1) * 8, End: uint64(len(wire)-1)*8 + 2}
		if !errors.Is(err, ErrSyntax) || !errors.As(err, &located) || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Location.Spans[0] != want {
			t.Fatalf("size=%d err=%v location=%+v want=%+v", size, err, located, want)
		}
	}
}

func TestReplayedFramingEnforcesOpenTypeCeiling(t *testing.T) {
	budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxOpenTypeBytes: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewBudgetBuffer(budget).ChargeOpenTypeFraming(3); !errors.Is(err, ErrLimit) {
		t.Fatalf("replayed open frame exceeded ceiling: %v", err)
	}
}
