// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestDuplicateUnknownValidationReportLimit(t *testing.T) {
	field, err := s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	body := s19.ErrorIndication{ProtocolIEs: s11.ErrorIndicationIEContainer{field, field}}
	report, err := s19.ValidateErrorIndication(&body, aper.WithValidationLimits(aper.Limits{MaxReports: 2}))
	if !errors.Is(err, aper.ErrLimit) || len(report.Issues) > 2 {
		t.Fatalf("duplicate report overflow: %+v %v", report, err)
	}
	report, err = s19.ValidateErrorIndication(&body, aper.WithValidationLimits(aper.Limits{MaxReports: 3}))
	if err != nil || len(report.Issues) != 3 {
		t.Fatalf("duplicate reports: %+v %v", report, err)
	}
	repeated := 0
	for _, issue := range report.Issues {
		if issue.Code == s00.RepeatedIE {
			repeated++
		}
	}
	if repeated != 1 {
		t.Fatalf("repeated findings=%d", repeated)
	}
	if _, err := s19.NewErrorIndication(body.ProtocolIEs); !errors.Is(err, aper.ErrInvalidValue) {
		t.Fatalf("duplicate unknown built: %v", err)
	}
}
