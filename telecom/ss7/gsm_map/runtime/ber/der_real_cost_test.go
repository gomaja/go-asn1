// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/der_real_cost_test.go; SHA-256 89984cf2f12b1957d75ad89d3ead86e2cbf6aca72278e6fe8a43e689ed032465.
package ber

import (
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
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
