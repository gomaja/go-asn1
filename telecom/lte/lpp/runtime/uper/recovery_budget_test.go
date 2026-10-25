// Code generated from LPP runtime source. DO NOT EDIT.

// Runtime source: runtime/uper/recovery_budget_test.go; SHA-256 196990584b30e64b28d990c751e875a0ca996c8c40ccdcc1abda5fda09c1df9b.
package uper

import (
	"errors"
	"runtime"
	"testing"
)

// A rolled-back candidate's first read is free. Re-reading the same bits is
// extra work, and removing the shared limit lets that retry succeed.

// Nest ::= SEQUENCE { data OCTET STRING, ...,
//
//	next Nest OPTIONAL, wide INTEGER (0..65535) OPTIONAL, after BOOLEAN OPTIONAL }
//
// Every level carries a one-octet wide addition, short of its required two.
// X.691 (02/2021) 19.8–19.9 and 11.2.1–11.2.2 bound next and wide separately.

// A callback cannot disguise exhaustion as recoverable truncation.

// The budget's widening and multiplication must also fit a 32-bit host.

func TestRecoveryWorkNestedRollback(t *testing.T) {
	var log ToleranceLog
	b := NewBitBufferFromBytes([]byte{0})
	if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &log}); err != nil {
		t.Fatal(err)
	}
	outerData, innerData := []byte{0}, []byte{0}
	for attempt := 0; attempt < 4; attempt++ {
		outer := ExtensionAdditions{present: []bool{true}}
		_, _, err := decodeKnownAddition(&outer, b, 0, outerData, func(child *BitBuffer) error {
			if _, err := child.ReadBits(8); err != nil {
				return err
			}
			inner := ExtensionAdditions{present: []bool{true}}
			_, _, err := decodeKnownAddition(&inner, child, 0, innerData, func(leaf *BitBuffer) error {
				if _, err := leaf.ReadBits(8); err != nil {
					return err
				}
				return ErrTruncated
			})
			if err != nil {
				return err
			}
			return ErrTruncated
		})
		if attempt < 3 {
			if err != nil || !outer.Recovered() || len(b.trace.pending) != attempt+1 {
				t.Fatalf("nested rollback: %v", err)
			}
		} else if !errors.Is(err, ErrResourceLimit) || outer.Recovered() {
			t.Fatalf("nested rollback refunded work: %v", err)
		}
	}
	if b.trace.work.used != 32 || len(log.Snapshot()) != 0 {
		t.Fatal("nested work or publication changed")
	}
}

func TestRecoveryWorkRejectsCopyBeforeAllocation(t *testing.T) {
	for _, packed := range []bool{false, true} {
		b := NewBitBufferFromBytes(nil)
		if err := b.SetDecodeOptions(DecodeOptions{ExtensionRecoveryTolerance: &ToleranceLog{}}); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 1<<20)
		first := ExtensionAdditions{present: []bool{true}}
		_, _, err := decodeKnownAddition(&first, b, 0, data, func(child *BitBuffer) error {
			_, _ = child.ReadBits(8)
			return ErrTruncated
		})
		if err != nil || !first.Recovered() {
			t.Fatalf("first pass rejected: %v", err)
		}
		a := ExtensionAdditions{present: []bool{true}}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, _, err = decodeKnownAddition(&a, b, 0, data, func(child *BitBuffer) error {
			if packed {
				_, err := child.ReadBitsToBytes(len(data) * 8)
				return err
			}
			_, err := child.ReadBytes(len(data))
			return err
		})
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrResourceLimit) || a.Recovered() || after.TotalAlloc-before.TotalAlloc > 32<<10 {
			t.Fatalf("packed=%v over-budget copy allocated: bytes=%d err=%v", packed, after.TotalAlloc-before.TotalAlloc, err)
		}
	}
}

// Root nesting does not create another bounded addition. Re-encoding and
// retaining every recovered enclosing value must still share the budget.
// RootNest ::= SEQUENCE { next RootNest OPTIONAL, ...,
//
//	wide INTEGER (0..65535) OPTIONAL }
