// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestKnownChoiceAdditionsDoNotConsumeReports(t *testing.T) {
	known, err := s00.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	field, err := s17.X2SetupRequestIEs().GlobalENBID().New(s05.GlobalENBID{PLMNIdentity: make([]byte, 3), ENBID: known})
	if err != nil {
		t.Fatal(err)
	}
	body := s20.X2SetupRequest{ProtocolIEs: s17.X2SetupRequestIEContainer{field, field}}
	wire, err := body.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	var value s20.X2SetupRequest
	report, err := value.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxReports: 1}))
	if err != nil || len(report.Observations) != 0 || len(report.Deviations) != 0 {
		t.Fatalf("known choice exhausted reports: %+v %v", report, err)
	}
}
