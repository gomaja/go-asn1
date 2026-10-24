// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestKnownChoiceAddsNoUnknownObservation(t *testing.T) {
	known, err := s00.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := known.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s00.ENBID
		report, err := value.UnmarshalAPER(wire, options...)
		if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
			t.Fatalf("known addition report=%+v err=%v", report, err)
		}
	}
}
