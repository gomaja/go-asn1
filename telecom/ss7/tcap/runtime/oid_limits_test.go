// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/oid_limits_test.go; SHA-256 f4f3868e48aeca25477827f3387f650ae7a4fc1c23d2bc5e393d9283c1ddf6a0.
package runtime_test

import (
	"errors"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"strings"
	"testing"
)

func TestOIDUint64CombinedRootBoundaries(t *testing.T) {
	for _, delta := range []uint64{0, 1, 79, 80, 81} {
		second := ^uint64(0) - delta
		v, err := runtime.ObjectIdentifierFromArcs(2, second)
		if err != nil {
			t.Fatal(err)
		}
		arcs, ok := v.Arcs()
		if !ok || len(arcs) != 2 || arcs[0] != 2 || arcs[1] != second {
			t.Fatal(arcs, ok)
		}
		if v.String() != v.BigArcs()[0].String()+"."+v.BigArcs()[1].String() {
			t.Fatal("incorrect combined root")
		}
	}
}

func TestOIDFormattingWidthPreflightBound(t *testing.T) {
	for _, size := range []int{1024, 8192, 65536, 1 << 20} {
		oid, err := runtime.ObjectIdentifierFromEncoded("\x2a\x81" + strings.Repeat("\x80", size-2) + "\x00")
		if err != nil {
			t.Fatal(err)
		}
		operation := func() {
			_, e := oid.StringChecked()
			if !errors.Is(e, runtime.ErrOIDTextLimit) {
				t.Fatal(e)
			}
		}
		allocated, _ := allocationCost(t, 5, operation)
		// Repeated scans can be quadratic without allocating more memory.
		elapsed := minimumTime(t, operation)
		if int64(allocated) > 256 || elapsed.Nanoseconds() > 100000 {
			t.Fatalf("size=%d time=%s bytes=%d", size, elapsed, allocated)
		}
		t.Logf("size=%d time=%s bytes=%d", size, elapsed, allocated)
	}
}
