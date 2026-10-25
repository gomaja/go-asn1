// Code generated from LTE RRC runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/inline_bitmap_test.go; SHA-256 b2cebea2059734a9eb953e1acc0558fcff1887f7a8eae16e9df0c1a04f6c34b8.
package uper

import (
	"bytes"
	"errors"
	"testing"
)

// Synthetic X.691 §§19.2–19.4 case: parent map 01, child map
// 000000000, padded under §11.1.3.1. The conformant octets are 4000.
func inlineBitmapReader(t *testing.T, data []byte, options DecodeOptions) *BitBuffer {
	t.Helper()
	bb := NewBitBufferFromBytes(data)
	if err := bb.SetDecodeOptions(options); err != nil {
		t.Fatal(err)
	}
	if _, err := bb.ReadBits(2); err != nil {
		t.Fatal(err)
	}
	return bb
}

func TestInlineBitmapRecoveryAndReplay(t *testing.T) {
	var log ToleranceLog
	bb := inlineBitmapReader(t, []byte{0x40}, DecodeOptions{InlineBitmapRecoveryTolerance: &log})
	mark := bb.EnterComponent("NonCriticalExtension")
	final, accepted, err := bb.RecoverEmptyInlineBitmap(9)
	bb.LeaveComponent(mark)
	if err != nil || !accepted || !final.InferredInlineBitmap() || bb.BitPos() != 8 {
		t.Fatalf("accepted=%v inferred=%v pos=%d err=%v", accepted, final.InferredInlineBitmap(), bb.BitPos(), err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("record published before top-level success")
	}
	if _, err := CaptureFinalBits(bb, "Parent"); err != nil {
		t.Fatal(err)
	}
	records := log.Snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%+v", records)
	}
	r := records[0]
	if r.Path != "Parent.NonCriticalExtension" || r.Kind != ToleratedIncompleteInlineBitmap || r.Offset != 8 || r.Bits.BitLength != 6 || r.Missing != 3 || !bytes.Equal(r.Bits.Bytes, []byte{0}) {
		t.Fatalf("record=%+v", r)
	}
	for _, tc := range []struct {
		name   string
		prefix uint64
		width  int
		bits   uint64
		want   []byte
	}{
		{"unchanged", 1, 9, 0, []byte{0x40}},
		{"edited parent", 3, 9, 0, []byte{0xc0, 0}},
		{"edited bitmap", 1, 9, 1, []byte{0x40, 0x20}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := NewBitBuffer()
			if err := out.WriteBits(tc.prefix, 2); err != nil {
				t.Fatal(err)
			}
			if err := out.WriteBits(tc.bits, tc.width); err != nil {
				t.Fatal(err)
			}
			AppendTruncatedExtension(out, final)
			got, err := out.CompleteBytesWithFinalPadding(FinalPadding{})
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("got=%x want=%x err=%v", got, tc.want, err)
			}
		})
	}
	merged := FinalPaddingOf(CompletePadding{count: 1}).WithRecords(final)
	if !merged.InferredInlineBitmap() {
		t.Fatal("final padding merge lost inferred absence")
	}
	// Provenance access never exposes the log's mutable storage.
	records[0].Bits.Bytes[0] = 0xff
	if log.Snapshot()[0].Bits.Bytes[0] != 0 {
		t.Fatal("snapshot aliases record bytes")
	}
}

func TestInlineBitmapRecoveryBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		data                     []byte
		prefix, width            int
		enabled, blocked, nested bool
		want                     bool
		truncated                bool
	}{
		{"default", []byte{0x40}, 2, 9, false, false, false, false, false},
		{"complete bitmap", []byte{0x40, 0}, 2, 9, true, false, false, false, false},
		{"one missing", []byte{0x40}, 2, 7, true, false, false, true, false},
		{"one received", []byte{0x40}, 7, 9, true, false, false, true, false},
		{"none received", []byte{0x40}, 8, 9, true, false, false, true, false},
		{"none received later field", []byte{0x40}, 8, 9, true, true, false, false, false},
		{"none received nested bounded input", []byte{0x40}, 8, 9, true, false, true, false, false},
		{"none received fragmented map", []byte{0x40}, 8, 65536, true, false, false, false, false},
		{"none received empty map", []byte{0x40}, 8, 0, true, false, false, false, false},
		{"none received option off", []byte{0x40}, 8, 9, false, false, false, false, false},
		{"received one", []byte{0x60}, 2, 9, true, false, false, false, true},
		{"last received one", []byte{0x41}, 2, 9, true, false, false, false, true},
		{"later field", []byte{0x40}, 2, 9, true, true, false, false, false},
		{"nested bounded input", []byte{0x40}, 2, 9, true, false, true, false, false},
		{"fragmented map", []byte{0x40}, 2, 65536, true, false, false, false, false},
		{"empty map", []byte{0x40}, 2, 0, true, false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log ToleranceLog
			options := DecodeOptions{}
			if tc.enabled {
				options.InlineBitmapRecoveryTolerance = &log
			}
			bb := NewBitBufferFromBytes(tc.data)
			if err := bb.SetDecodeOptions(options); err != nil {
				t.Fatal(err)
			}
			if tc.nested {
				bb = NewNestedDecodeBuffer(tc.data, bb)
			}
			if _, err := bb.ReadBits(tc.prefix); err != nil {
				t.Fatal(err)
			}
			outer := bb.EnterInlineBitmapTail(!tc.blocked)
			inner := bb.EnterInlineBitmapTail(true)
			final, accepted, err := bb.RecoverEmptyInlineBitmap(tc.width)
			bb.LeaveInlineBitmapTail(inner)
			bb.LeaveInlineBitmapTail(outer)
			if accepted != tc.want || errors.Is(err, ErrTruncated) != tc.truncated || err != nil && !tc.truncated {
				t.Fatalf("accepted=%v err=%v", accepted, err)
			}
			if final.InferredInlineBitmap() != tc.want {
				t.Fatal("inference marker differs")
			}
			if accepted {
				if _, err := CaptureFinalBits(bb, "Parent"); err != nil {
					t.Fatal(err)
				}
				records := log.Snapshot()
				if len(records) != 1 {
					t.Fatalf("records=%+v", records)
				}
				r := records[0]
				received := len(tc.data)*8 - tc.prefix
				if r.Kind != ToleratedIncompleteInlineBitmap || r.Path != "Parent" || r.Offset != len(tc.data)*8 || r.Bits.BitLength != received || r.Missing != tc.width-received || len(r.Bits.Bytes) != (received+7)/8 {
					t.Fatalf("record=%+v", r)
				}
				return
			}
			if !accepted && !tc.truncated && bb.BitPos() != tc.prefix {
				t.Fatal("ineligible probe consumed input")
			}
			if len(log.Snapshot()) != 0 {
				t.Fatal("record published before success")
			}
		})
	}
}

func TestInlineBitmapScopeRestoration(t *testing.T) {
	var log ToleranceLog
	bb := inlineBitmapReader(t, []byte{0x40}, DecodeOptions{InlineBitmapRecoveryTolerance: &log})
	outer := bb.EnterInlineBitmapTail(false)
	inner := bb.EnterInlineBitmapTail(true)
	if _, accepted, _ := bb.RecoverEmptyInlineBitmap(9); accepted {
		t.Fatal("inner final scope erased outer blocker")
	}
	bb.LeaveInlineBitmapTail(inner)
	bb.LeaveInlineBitmapTail(outer)
	if _, accepted, err := bb.RecoverEmptyInlineBitmap(9); err != nil || !accepted {
		t.Fatalf("scope not restored: %v %v", accepted, err)
	}
}

func TestInlineBitmapDefaultHasNoAllocation(t *testing.T) {
	if got := testing.AllocsPerRun(100, func() {
		var bb BitBuffer
		mark := bb.EnterInlineBitmapTail(false)
		final, accepted, err := bb.RecoverEmptyInlineBitmap(9)
		bb.LeaveInlineBitmapTail(mark)
		if accepted || err != nil || !final.IsZero() {
			panic("strict helper changed")
		}
	}); got != 0 {
		t.Fatalf("strict allocations=%v", got)
	}
}

func TestInlineBitmapFragmentFinality(t *testing.T) {
	for _, tc := range []struct {
		name        string
		determinant byte
		want        bool
	}{
		{"fragment requiring another determinant", 0xc1, false},
		{"final length determinant", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log ToleranceLog
			bb := NewBitBufferFromBytes([]byte{tc.determinant, 0})
			if err := bb.SetDecodeOptions(DecodeOptions{InlineBitmapRecoveryTolerance: &log}); err != nil {
				t.Fatal(err)
			}
			_, err := DecodeLengthFragments(bb, false, func(_, _ int64) error {
				_, accepted, err := bb.RecoverEmptyInlineBitmap(9)
				if err != nil {
					return err
				}
				if accepted != tc.want {
					t.Fatalf("accepted=%v want=%v", accepted, tc.want)
				}
				if !accepted {
					return ErrTruncated
				}
				return nil
			})
			if tc.want && err != nil || !tc.want && !errors.Is(err, ErrTruncated) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestInlineBitmapWithPaddingObservations(t *testing.T) {
	for _, tc := range []struct {
		name          string
		input         []byte
		inline        bool
		wantInference bool
		wantPadding   int
	}{
		{"incomplete bitmap", []byte{0x40}, true, true, 0},
		{"complete zero padded", []byte{0x40, 0}, true, false, 0},
		{"complete nonzero padding", []byte{0x40, 1}, true, false, 1},
		{"padding alone", []byte{0x40}, false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inline, padding ToleranceLog
			opts := DecodeOptions{PaddingObservations: &padding}
			if tc.inline {
				opts.InlineBitmapRecoveryTolerance = &inline
			}
			bb := inlineBitmapReader(t, tc.input, opts)
			_, accepted, err := bb.RecoverEmptyInlineBitmap(9)
			if err != nil || accepted != tc.wantInference {
				t.Fatalf("accepted=%v err=%v", accepted, err)
			}
			if !accepted {
				_, err = bb.ReadBits(9)
				if !tc.inline {
					if !errors.Is(err, ErrTruncated) {
						t.Fatalf("padding-only decode=%v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := CaptureFinalBits(bb, "Parent"); err != nil {
				t.Fatal(err)
			}
			if len(inline.Snapshot()) != 0 && !tc.wantInference || len(inline.Snapshot()) == 0 && tc.wantInference {
				t.Fatal("inference record differs")
			}
			if len(padding.Snapshot()) != tc.wantPadding {
				t.Fatalf("padding records=%+v", padding.Snapshot())
			}
			if tc.wantPadding != 0 {
				r := padding.Snapshot()[0]
				if r.Offset != 11 || r.Bits.BitLength != 5 || len(r.InputSpans) != 1 || r.InputSpans[0].Offset != 11 || r.InputSpans[0].BitLength != 5 {
					t.Fatalf("padding provenance=%+v", r)
				}
			}
			if tc.wantInference {
				r := inline.Snapshot()[0]
				if r.Bits.BitLength != 6 || r.Offset != 8 || r.Missing != 3 {
					t.Fatalf("inference provenance=%+v", r)
				}
			}
		})
	}
}

func TestInlineBitmapRecoveryRespectsChildDepth(t *testing.T) {
	var log ToleranceLog
	bb := inlineBitmapReader(t, []byte{0x40}, DecodeOptions{InlineBitmapRecoveryTolerance: &log, Limits: DecodeLimits{MaxDepth: 1}})
	if err := bb.EnterDecodeValue(); err != nil {
		t.Fatal(err)
	}
	if _, accepted, err := bb.RecoverEmptyInlineBitmap(9); !errors.Is(err, ErrResourceLimit) || accepted {
		t.Fatalf("child depth bypassed: accepted=%t error=%v", accepted, err)
	}
	if len(log.Snapshot()) != 0 {
		t.Fatal("limited decode published recovery")
	}
}

func TestInlineBitmapElementFinality(t *testing.T) {
	for _, tc := range []struct {
		index, count int64
		last         bool
	}{{0, 1, true}, {0, 2, false}, {1, 2, true}, {-1, 1, false}, {0, 0, false}, {0, -1, false}} {
		var log ToleranceLog
		bb := inlineBitmapReader(t, []byte{0x40}, DecodeOptions{InlineBitmapRecoveryTolerance: &log})
		mark := bb.EnterInlineBitmapElement(tc.index, tc.count)
		_, accepted, err := bb.RecoverEmptyInlineBitmap(9)
		bb.LeaveInlineBitmapTail(mark)
		if err != nil || accepted != tc.last {
			t.Fatalf("index=%d count=%d accepted=%t err=%v", tc.index, tc.count, accepted, err)
		}
	}
}
