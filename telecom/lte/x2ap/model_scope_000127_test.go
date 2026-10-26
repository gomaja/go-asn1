// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	testing "testing"
)

func TestEditedLeafAllocationGrowthIsLinear(t *testing.T) {
	c := s14.CriticalityDiagnosticsIEListCodec()
	measure := func(n int) float64 {
		wire := replayListWire(t, n)
		return testing.AllocsPerRun(10, func() {
			v, _, err := c.DecodeAPER(wire)
			if err != nil {
				panic(err)
			}
			v.Value[n/2].IEID = 9
			if _, err := c.EncodeAPER(v); err != nil {
				panic(err)
			}
		})
	}
	previous := measure(8)
	for _, n := range []int{16, 32, 64, 128} {
		next := measure(n)
		t.Logf("items=%d allocations=%v previous=%v", n, next, previous)
		if next > 2.25*previous {
			t.Fatalf("edited leaf growth is superlinear: %v -> %v", previous, next)
		}
		previous = next
	}
}
