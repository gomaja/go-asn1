// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/associated_allocation_test.go; SHA-256 7be26649a0f0a0b23559090ec5aea9e6f90dc462a9dac0cc79742f3cafe930f1.
package ber

import (
	"fmt"
	"testing"
)

func associatedDERAllocationWire(identifier byte, size int) []byte {
	contents := append([]byte{0xa0, 2, 0x85, 0, 0x82}, EncodeLength(size)...)
	contents = append(contents, make([]byte, size)...)
	return append(append([]byte{identifier}, EncodeLength(len(contents))...), contents...)
}

func TestAssociatedDERAllocationBound(t *testing.T) {
	for _, identifier := range []byte{0x2b, 0x3d} {
		for _, size := range []int{0, 256, 1024, 8192} {
			t.Run(fmt.Sprintf("tag-%x/data-%d", identifier, size), func(t *testing.T) {
				wire := associatedDERAllocationWire(identifier, size)
				limit := float64(4)
				if size > 0 {
					limit = 12
				}
				allocations := testing.AllocsPerRun(100, func() {
					if err := ValidateDEREncodedElement(wire); err != nil {
						t.Fatal(err)
					}
				})
				if allocations > limit {
					t.Fatalf("DER allocations = %.0f, bound %.0f", allocations, limit)
				}
			})
		}
	}
}

func BenchmarkAssociatedDERAllocation(b *testing.B) {
	for _, identifier := range []byte{0x2b, 0x3d} {
		b.Run(fmt.Sprintf("tag-%x", identifier), func(b *testing.B) {
			wire := associatedDERAllocationWire(identifier, 1024)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ValidateDEREncodedElement(wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
