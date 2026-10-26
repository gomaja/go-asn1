// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/lppa_closure_test.go; SHA-256 846f7700c1d93001fbd3e00af0426e82041fb9d9b095635195b908ac3a9d425b.
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
