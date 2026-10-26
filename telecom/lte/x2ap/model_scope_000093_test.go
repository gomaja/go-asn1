// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestEnvelopeFindingsRespectTheSameReportCeiling(t *testing.T) {
	wire := receiverUnknownWire(t, 2)
	var value s19.X2APPDU
	if _, err := value.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	value.InitiatingMessage.Criticality = s00.CriticalityReject
	report, err := s20.ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 2}))
	var located *aper.DecodeError
	if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || located.Location.Path == "" || len(report.Issues) > 2 || located.Location.HasWireLocation {
		t.Fatalf("report=%+v err=%v location=%+v", report, err, located)
	}
	if _, err := s20.ValidateMessage(&value, aper.WithValidationLimits(aper.Limits{MaxReports: 3})); err != nil {
		t.Fatal(err)
	}
}
