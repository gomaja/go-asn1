// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s21"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestReceiverReportsOnlyUnknownBoundaries(t *testing.T) {
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		opaque, err := s20.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		unknown, err := s21.NewX2APPDUInitiatingMessage(opaque)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := unknown.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var pdu s20.X2APPDU
		report, err := pdu.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Kind != aper.UnknownProcedure {
			t.Fatalf("procedure report=%+v err=%v", report, err)
		}
		choice, err := s20.NewX2APPDUUnknownExtension(7, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err = choice.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		report, err = pdu.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Kind != aper.UnknownExtension {
			t.Fatalf("choice report=%+v err=%v", report, err)
		}
		known := s06.CriticalityDiagnostics{}
		if err := known.SetExtension(0, []byte{0}); err != nil {
			t.Fatal(err)
		}
		wire, err = known.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded s06.CriticalityDiagnostics
		report, err = decoded.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 || report.Observations[0].Rule.Clause != "§9.3.5" {
			t.Fatalf("sequence source rule=%+v err=%v", report, err)
		}

	}
}
