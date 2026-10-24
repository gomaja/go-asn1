package lppa

import (
	q23 "bytes"
	q21 "errors"
	q10 "fmt"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"

	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q24 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q20 "math/big"
	q15 "strings"
	q8 "testing"
)

// TS 36.455 V19.0.0 §9.3.5 defines IDs 25 and 27 only in
// ResultNR-Item-ExtIEs. §10 adopts TS 36.413 §10's context checks.
func TestKnownExtensionIDsAreForbiddenInOtherTables(t *q8.T) {
	for _, id := range []ProtocolIEID{25, 27, 65532} {
		t.Run(q10.Sprint(id), func(t *q8.T) {
			field, err := ResultsPerSSBIndexItemExtIEs().NewOpaque(id, CriticalityIgnore, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			item := ResultsPerSSBIndexItem{IEExtensions: ResultsPerSSBIndexItemExtIEsExtContainer{field}}
			report := ValidationReport{Complete: true}
			bridge0.BridgeWalkValidationResultsPerSSBIndexItem(&item, &report, "ResultsPerSSBIndexItem", false)
			want := ValidationSeverityError
			if id == 65532 {
				want = ValidationSeverityUnrecognized
			}
			if len(report.Issues) != 1 || report.Issues[0].Code != NotAllowed || report.Issues[0].Severity != want || report.Issues[0].IEID != id || !report.Issues[0].HasIEID || !q15.Contains(string(report.Issues[0].Location.Path), "IEExtensions[0]") || report.Issues[0].Rule.Clause != "§10" {
				t.Errorf("extension validation: %+v", report)
			}
			// Exercise the same empty extension table through a complete message
			// and its checked builder, without unrelated structural violations.
			ext, err := ECGIExtIEs().NewOpaque(id, CriticalityIgnore, []byte{0})
			if err != nil {
				t.Fatal(err)
			}
			result := ECIDMeasurementResult{ServingCellID: ECGI{PLMNIdentity: []byte{0, 0, 0}, EUTRANcellIdentifier: q19.BitString{Bytes: make([]byte, 4), BitLength: 28}, IEExtensions: ECGIExtIEsExtContainer{ext}}, ServingCellTAC: []byte{0, 0}}
			table := ECIDMeasurementReportIEs()
			fields := ECIDMeasurementReportIEContainer{eCIDMeasurementReportIEFieldUnknownBoundaryMust(table.ESMLCUEMeasurementID().New(q20.NewInt(1))), eCIDMeasurementReportIEFieldUnknownBoundaryMust(table.ENBUEMeasurementID().New(q20.NewInt(2))), eCIDMeasurementReportIEFieldUnknownBoundaryMust(table.ECIDMeasurementResult().New(result))}
			_, err = NewECIDMeasurementReport(fields)
			if id == 65532 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var build *BuildError
			if !q21.As(err, &build) || len(build.Issues) != 1 || build.Issues[0].Code != NotAllowed || build.Issues[0].IEID != id {
				t.Fatalf("builder accepted forbidden extension: %v", err)
			}
		})
	}
}

// X.691 (02/2021) §§19.8–19.9: index zero is the typed bare
// sIB1-NB-Subframe-TDD addition, not opaque content.
func TestSequenceUnknownAccessorsExcludeKnownAddition(t *q8.T) {
	value := int64(1)
	body := NPRSSubframePartB{SIB1NBSubframeTDD: &value}
	if got := body.Extensions(); len(got) != 0 {
		t.Fatalf("fresh known addition shown as opaque: %+v", got)
	}
	if err := body.SetExtension(1, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var decoded NPRSSubframePartB
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	if got := decoded.Extensions(); len(got) != 1 || got[0].Index() != 1 || !q23.Equal(got[0].Contents(), []byte{0x80}) {
		t.Errorf("unknown extensions include known index: %+v", got)
	}
	for _, index := range []uint64{0, 16383, ^uint64(0)} {
		for _, operation := range []string{"set", "remove"} {
			t.Run(q10.Sprintf("%s/%d", operation, index), func(t *q8.T) {
				var err error
				if operation == "set" {
					err = decoded.SetExtension(index, []byte{0})
				} else {
					err = decoded.RemoveExtension(index)
				}
				var located *q19.DecodePathError
				want := q24.ErrInvalidValue
				if operation == "set" && index >= 16383 {
					want = q24.ErrLimit
				}
				if !q21.As(err, &located) || !q15.Contains(located.Path, q10.Sprintf("NPRSSubframePartB.Extensions[%d]", index)) || !q21.Is(err, want) {
					t.Errorf("invalid index lacks located error: %v", err)
				}
				replay, replayErr := decoded.MarshalAPER()
				if replayErr != nil || !q23.Equal(replay, wire) {
					t.Errorf("refused operation changed value: %x, %v", replay, replayErr)
				}
			})
		}
	}
	if decoded.SIB1NBSubframeTDD == nil || *decoded.SIB1NBSubframeTDD != 1 {
		t.Fatal("known addition changed")
	}
	if err := decoded.RemoveExtension(1); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Extensions()) != 0 {
		t.Fatal("unknown addition survived removal")
	}
	if decoded.SIB1NBSubframeTDD == nil || *decoded.SIB1NBSubframeTDD != 1 {
		t.Fatal("removing unknown changed known addition")
	}
}
func TestOpaqueConstructorsRefuseKnownSelectors(t *q8.T) {
	// The two known BitmapsforNPRS extension arms and the resultNR arm
	// are declared in TS 36.455 V19.0.0 §9.3.5.
	for _, index := range []uint64{0, 1} {
		if _, err := NewBitmapsforNPRSUnknownExtension(index, []byte{0}); err == nil {
			t.Errorf("known bitmap arm %d accepted as opaque", index)
		}
	}
	if _, err := NewInterRATMeasuredResultsValueUnknownExtension(0, []byte{0}); err == nil {
		t.Fatal("known resultNR arm accepted as opaque")
	}
	for _, id := range []ProtocolIEID{25, 27} {
		if _, err := ResultNRItemExtIEs().NewOpaque(id, CriticalityIgnore, []byte{0}); err == nil {
			t.Errorf("known extension ID %d accepted as opaque", id)
		}
	}
	if _, err := ECIDMeasurementInitiationRequestIEs().NewOpaque(2, CriticalityReject, []byte{0}); err == nil {
		t.Fatal("known IE accepted as opaque")
	}
}
