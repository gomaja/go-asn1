// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// Grow the source IE count and nested list count independently. Accounted work
// includes the exact semantic comparison and changed framing, without timing.
func TestEditedLeafIEAndListWorkGrowsLinearly(t *testing.T) {
	for _, lists := range []bool{false, true} {
		name := "ies"
		if lists {
			name = "list-items"
		}
		t.Run(name, func(t *testing.T) {
			var previousAllocations float64
			var previousWork, previousBytes uint64
			for _, n := range []int{8, 16, 32, 64, 128} {
				var fields s11.ErrorIndicationIEContainer
				if lists {
					diagnostics := s06.CriticalityDiagnostics{IEsCriticalityDiagnostics: make(s06.CriticalityDiagnosticsIEList, n)}
					fields = s11.ErrorIndicationIEContainer{errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().CriticalityDiagnostics().New(diagnostics))}
				} else {
					fields = make(s11.ErrorIndicationIEContainer, n)
					for i := range fields {
						fields[i] = errorIndicationIEFieldapiMust(s11.ErrorIndicationIEs().Cause().New(apiCause()))
					}
				}
				body := s19.ErrorIndication{ProtocolIEs: fields}
				original := s19.X2APPDU{Choice: s00.X2APPDUChoiceInitiatingMessage, InitiatingMessage: &s19.InitiatingMessage{ProcedureCode: s00.IdErrorIndication, Criticality: s00.CriticalityIgnore, Value: s19.X2apInternalConstructT15InitiatingValueF4codeF19bodyErrorIndication(s00.IdErrorIndication, &body)}}
				wire := listByteapiMust(original.MarshalAPER())
				var usage aper.DecodeUsage
				allocations := testing.AllocsPerRun(10, func() {
					var value s19.X2APPDU
					if _, err := value.UnmarshalAPER(wire); err != nil {
						panic(err)
					}
					decoded, _ := value.InitiatingMessage.Value.AsErrorIndication()
					if lists {
						diagnostics, _ := decoded.ProtocolIEs[0].Value.AsCriticalityDiagnostics()
						diagnostics.IEsCriticalityDiagnostics[n/2].IEID = 9
					} else {
						cause, _ := decoded.ProtocolIEs[n/2].Value.AsCause()
						*cause = causeapiMust(s00.NewCauseMisc(s00.CauseMisc(3)))
					}
					budget, err := aper.EncodeBudgetValue()
					if err != nil {
						panic(err)
					}
					out, err := value.MarshalAPER()
					if err != nil {
						panic(err)
					}
					budgeted, err := s19.X2apInternalX2APPDUMarshalAPERBudget(&value, &budget, false)
					if err != nil || !bytes.Equal(out, budgeted) {
						panic("budgeted encoding differs from public encoding")
					}
					if bytes.Equal(out, wire) {
						panic("edited leaf was replayed")
					}
					usage = aper.NewBudgetBuffer(&budget).Usage()
				})
				t.Logf("size=%d allocations=%v work=%d charged-bytes=%d", n, allocations, usage.Work, usage.AllocatedBytes)
				if previousAllocations != 0 && (allocations > 2.25*previousAllocations || float64(usage.Work) > 2.25*float64(previousWork) || float64(usage.AllocatedBytes) > 2.25*float64(previousBytes)) {
					t.Fatalf("superlinear edited-leaf growth: allocations=%v/%v work=%d/%d charged-bytes=%d/%d", allocations, previousAllocations, usage.Work, previousWork, usage.AllocatedBytes, previousBytes)
				}
				previousAllocations, previousWork, previousBytes = allocations, usage.Work, usage.AllocatedBytes
			}
		})
	}
}
