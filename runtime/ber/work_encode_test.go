package ber

import "testing"

func TestValidateBEREncodedElementScalesWithInput(t *testing.T) {
	// X.690 (02/2021) §8.15 permits one constructed value with many
	// components. Validation must not allocate in proportion to their count.
	for _, count := range []int{128, 2048, 32768} {
		children := make([]byte, 0, count*2)
		for range count {
			children = append(children, 5, 0)
		}
		wire, err := EncodeSequence(children)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateBEREncodedElement(wire); err != nil {
			t.Fatalf("%d components: %v", count, err)
		}
		allocations := testing.AllocsPerRun(3, func() {
			if err := ValidateBEREncodedElement(wire); err != nil {
				panic(err)
			}
		})
		if allocations > 32 {
			t.Fatalf("%d components: %.0f allocations, want at most 32", count, allocations)
		}
	}
}
