// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestUnreportedSequenceExtensionAllocations(t *testing.T) {
	value := s06.CriticalityDiagnostics{}
	if err := value.SetExtension(127, []byte{0}); err != nil {
		t.Fatal(err)
	}
	wire, err := value.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	allocations := testing.AllocsPerRun(100, func() {
		var decoded s06.CriticalityDiagnostics
		if err := s06.X2apInternalCriticalityDiagnosticsUnmarshalAPERFrom(&decoded, aper.NewBitBufferFromBytes(wire)); err != nil {
			panic(err)
		}
	})
	t.Logf("unreported extension allocations=%v", allocations)
	if allocations > 13 {
		t.Fatalf("unreported extension allocated %v times", allocations)
	}
}
