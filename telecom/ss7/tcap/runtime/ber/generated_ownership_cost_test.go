// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/generated_ownership_cost_test.go; SHA-256 d3014129cb4a79753e8257a9d4a4c4b216f484caa52f2fc918b50309a7a6e9a1.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"testing"
)

func TestGeneratedInputOwnershipAllocations(t *testing.T) {
	for _, size := range []int{1, 32, 256, 8192} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			// X.690 (02/2021) §§8.7.1, 8.9: a primitive OCTET STRING
			// within a definite-length SEQUENCE.
			contents, err := EncodeOctetString(bytes.Repeat([]byte{'A'}, size))
			if err != nil {
				t.Fatal(err)
			}
			wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}, contents)
			if err != nil {
				t.Fatal(err)
			}
			allocations := testing.AllocsPerRun(1000, func() {
				options := TrackBERForm(nil)
				owned, err := OwnGeneratedBERInput(wire, options)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(owned, wire) || &owned[0] == &wire[0] {
					t.Fatal("ownership must retain an independent, unchanged input")
				}
			})
			// Strict ownership needs only the input copy, form marker and
			// option slice, at every size. Tolerant reports have private state.
			if allocations > 3 {
				t.Fatalf("input ownership allocated %.0f objects, want at most 3", allocations)
			}
			t.Logf("ownership allocations: %.0f", allocations)
		})
	}
}
