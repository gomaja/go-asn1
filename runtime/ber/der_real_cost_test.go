package ber

import (
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/runtime/tag"
)

func TestDERDecimalRealValidationCost(t *testing.T) {
	// X.690 (02/2021) §11.3.2 and ISO 6093 NR3 define a lexical
	// canonical form. Validation needs a scan, not bigint conversion.
	for _, text := range []string{strings.Repeat("7", 1_000_000) + ".E+0", "1.E" + strings.Repeat("7", 1_000_000)} {
		wire, err := EncodeTLV(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagReal}, append([]byte{3}, text...))
		if err != nil {
			t.Fatal(err)
		}
		for _, validate := range []func([]byte) error{ValidateDERElement, func(b []byte) error { _, err := ValidateDERTLV(b); return err }} {
			allocations := testing.AllocsPerRun(1, func() {
				if err := validate(wire); err != nil {
					t.Fatal(err)
				}
			})
			if allocations > 8 {
				t.Fatalf("decimal validation allocated %.0f objects; want constant scan workspace <= 8", allocations)
			}
		}
	}
}
