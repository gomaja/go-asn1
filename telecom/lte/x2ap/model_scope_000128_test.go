// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	testing "testing"
)

func TestUnchangedLargeValueCopiesOnlyItsResult(t *testing.T) {
	wire := replayListWire(t, 128)
	var value s14.CriticalityDiagnosticsIEListComplete
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(20, func() {
		out, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(out, wire) {
			panic("large replay differs")
		}
	})
	t.Logf("unchanged large encode=%v", allocations)
	if allocations != 1 {
		t.Fatalf("unchanged encode allocates %v, want one result", allocations)
	}
}
