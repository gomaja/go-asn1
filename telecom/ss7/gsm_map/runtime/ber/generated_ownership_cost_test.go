// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/generated_ownership_cost_test.go; SHA-256 1529cfaff9d6087804bbdd619534884b885e20222c09bf484c67252828a22f59.
package ber

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
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
				options := TrackMAPForm(nil)
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
