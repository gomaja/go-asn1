// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/lppa_closure_test.go; SHA-256 cf0b9e7ee50540e84f4cbe6159e8b0c0d1f333bf26f05ed99f83c922335659fb.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestS1APPrimitiveOpenTypeCompletion(t *testing.T) {
	// dispatch.go decodes ReportCharacteristics with this two-root enum and
	// completes its primitive open type, requiring zero padding under X.691 (02/2021) §11.1.4.
	bb := NewBitBufferFromBytes([]byte{0x40})
	value, err := DecodeEnumeratedAligned(bb, 2, true)
	if err != nil || value != 1 {
		t.Fatalf("enum=%d: %v", value, err)
	}
	complete, err := CompleteOpenTypeValue(bb, value)
	if err != nil || complete.Value != 1 {
		t.Fatalf("complete=%+v: %v", complete, err)
	}
	if bits, count := complete.ReceivedPadding().Bits(); bits != 0 || count != 0 {
		t.Fatalf("padding=%d/%d", bits, count)
	}
	writer := NewBitBuffer()
	if err := EncodeEnumeratedAligned(writer, complete.Value, 2, true); err != nil {
		t.Fatal(err)
	}
	replay, err := writer.CompleteBytesWithPadding(complete.ReceivedPadding())
	if err != nil || !bytes.Equal(replay, []byte{0x40}) {
		t.Fatalf("replay=%x: %v", replay, err)
	}
	for _, tc := range []struct {
		data []byte
		want error
	}{
		{[]byte{0x7f, 0}, ErrExtraData}, {nil, ErrTruncated},
	} {
		bb := NewBitBufferFromBytes(tc.data)
		if len(tc.data) != 0 {
			if _, err := DecodeEnumeratedAligned(bb, 2, true); err != nil {
				t.Fatal(err)
			}
		}
		got, err := CompleteOpenTypeValue(bb, value)
		if got != nil || !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "open type") {
			t.Fatalf("data=%x complete=%+v: %v", tc.data, got, err)
		}
	}
	bb = NewBitBufferFromBytes([]byte{0x40})
	if _, err := DecodeEnumeratedAligned(bb, 2, true); err != nil {
		t.Fatal(err)
	}
	final, err := CaptureFinalBits(bb, "ReportCharacteristics")
	if err != nil || !final.IsZero() {
		t.Fatalf("final padding=%+v: %v", final, err)
	}
	if suffix := final.Trailing(); suffix.BitLength != 0 || len(suffix.Bytes) != 0 {
		t.Fatalf("APER padding created suffix: %+v", suffix)
	}
}

func TestS1APUpperOnlyIntegerBound(t *testing.T) {
	upper := int64(10)
	for _, value := range []int64{-11, 0, 10, 11} {
		writer := NewBitBuffer()
		err := EncodeIntegerAligned(writer, value, nil, &upper, false)
		if value > upper {
			if !errors.Is(err, ErrConstraintViolation) || writer.BitPos() != 0 {
				t.Fatalf("upper-only encode %d: %v", value, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
		raw := NewBitBuffer()
		if err := EncodeUnconstrainedWholeNumberAligned(raw, value); err != nil {
			t.Fatal(err)
		}
		got, err := DecodeIntegerAligned(NewBitBufferFromBytes(raw.CompleteBytes()), nil, &upper, false)
		if got != value || (value > upper) != errors.Is(err, ErrConstraintViolation) {
			t.Fatalf("upper-only decode %d=>%d: %v", value, got, err)
		}
		if value > upper && !strings.HasSuffix(err.Error(), fmt.Sprintf("per: constraint violation: INTEGER %d above upper bound %d", value, upper)) {
			t.Fatalf("bound diagnostic: %v", err)
		}
	}
	if err := EncodeIntegerAligned(NewBitBuffer(), 11, nil, nil, false); err != nil {
		t.Fatalf("unbounded: %v", err)
	}
}

func TestS1APRecoveryListPaths(t *testing.T) {
	strict := NewBitBufferFromBytes([]byte{0})
	if strict.EnterIndex(3) != 0 || strict.RecoveryComponent("ResultNR") != -1 || strict.RecoveryIndex(2) != -1 {
		t.Fatal("strict path marks changed")
	}
	strict.LeaveComponent(-1)
	var log ToleranceLog
	parent := NewBitBufferFromBytes([]byte{0})
	if err := parent.setDecodeSettingsAligned(decodeSettings{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	component := parent.EnterComponent("Results")
	index := parent.EnterIndex(3)
	recoveryComponent := parent.RecoveryComponent("ResultNR")
	recoveryIndex := parent.RecoveryIndex(2)
	a := ExtensionAdditions{present: []bool{true}}
	decoded, _, err := decodeKnownAddition(&a, parent, 0, []byte{0x80}, func(child *BitBuffer) error {
		if _, err := child.ReadBits(3); err != nil {
			return err
		}
		return fmt.Errorf("leaf: %w", ErrTruncated)
	})
	if err != nil || decoded || !a.Recovered() {
		t.Fatalf("recover=%v: %v", decoded, err)
	}
	for _, mark := range []int{recoveryIndex, recoveryComponent, index, component} {
		parent.LeaveComponent(mark)
	}
	if _, err := CaptureFinalBits(parent, "Top"); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 || records[0].Path != "Top.Results[3].ResultNR[2].ExtData_[0]" || records[0].Kind.String() != "incomplete extension" || !errors.Is(records[0].Err, ErrTruncated) || !strings.HasPrefix(records[0].Err.Error(), records[0].Path+": leaf: ") {
		t.Fatalf("records=%+v", records)
	}
	if len(parent.trace.path) != 0 {
		t.Fatalf("path leaked: %+v", parent.trace.path)
	}
	// Cut-only options must not activate paths reserved for bounded recovery.
	if err := parent.setDecodeSettingsAligned(decodeSettings{TruncatedExtensionTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	if parent.RecoveryComponent("ResultNR") != -1 || parent.RecoveryIndex(2) != -1 || len(parent.trace.path) != 0 {
		t.Fatal("cut-only option enabled recovery paths")
	}
}

func TestS1APToleranceDiagnosticKinds(t *testing.T) {
	for kind, want := range map[ToleranceKind]string{ToleratedTrailingBits: "trailing bits", ToleratedContainedBits: "contained bits", ToleratedTruncatedExtension: "truncated extension", ToleratedIncompleteExtension: "incomplete extension", 255: "ToleranceKind(255)"} {
		if got := kind.String(); got != want {
			t.Fatalf("kind %d=%q, want %q", kind, got, want)
		}
	}
}
