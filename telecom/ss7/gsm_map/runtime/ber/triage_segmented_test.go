// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/triage_segmented_test.go; SHA-256 b97e28f6bc20bb41d2b3b57ff52f6cbfe756b71a84c1d0e790b44293632dcc6d.
package ber

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkBERSegmentedStrings(b *testing.B) {
	for _, kind := range []string{"octets", "bits"} {
		for _, depth := range []int{1, 10, 50, 100} {
			b.Run(fmt.Sprintf("%s/depth%d", kind, depth), func(b *testing.B) {
				leaf := bytes.Repeat([]byte{0xa0}, 64<<10)
				wire, err := EncodeOctetString(leaf)
				outer := byte(0x24)
				if kind == "bits" {
					wire, err = EncodeBitString(leaf, 4)
					outer = 0x23
				}
				if err != nil {
					b.Fatal(err)
				}
				for range depth {
					wire = append(append([]byte{outer, 0x80}, wire...), 0, 0)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(leaf)))
				b.ResetTimer()
				for range b.N {
					if kind == "bits" {
						if _, _, _, err := DecodeBitString(wire); err != nil {
							b.Fatal(err)
						}
					} else {
						if _, _, err := DecodeOctetString(wire); err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func TestBERSegmentedDestinationAllocation(t *testing.T) {
	wire := nestedOctets(t, 60, bytes.Repeat([]byte{0xa0}, 64<<10))
	allocations := testing.AllocsPerRun(10, func() {
		if _, _, err := DecodeOctetString(wire); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 4 {
		t.Fatalf("payload allocated per layer: %.0f", allocations)
	}
}
