// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestValidationGrowthIsLinear(t *testing.T) {
	var previous float64
	for _, size := range []int{1024, 2048, 4096} {
		fields := make(s11.ErrorIndicationIEContainer, size)
		for i := range fields {
			fields[i] = errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().NewOpaque(s00.ProtocolIEID(1000+i), s00.CriticalityIgnore, []byte{0}))
		}
		body := s19.ErrorIndication{ProtocolIEs: fields}
		allocations := testing.AllocsPerRun(3, func() {
			report, err := s19.ValidateErrorIndication(&body, aper.WithValidationLimits(aper.Limits{MaxReports: uint64(size)}))
			if err != nil || len(report.Issues) != size {
				panic(fmt.Sprintf("validation rows=%d want=%d err=%v", len(report.Issues), size, err))
			}
		})
		// Each doubling must stay below three times the allocation count; an
		// all-pairs search would grow by four times. Source rows stay constant.
		if previous != 0 && allocations > 3*previous {
			t.Fatalf("validation growth at %d: allocations=%g, previous=%g", size, allocations, previous)
		}
		previous = allocations
	}
}
