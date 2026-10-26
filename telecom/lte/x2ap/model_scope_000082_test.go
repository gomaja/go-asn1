// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	testing "testing"
)

// The source's mandatory extension row is required only inside a present
// container (TS 36.423 V19.1.0 §9.3.4, E-RABs-ToBeSetupRetrieve-ItemExtIEs).
func TestPortOptionalContainerMandatoryRow(t *testing.T) {
	var value s11.ERABsToBeSetupRetrieveItem
	if _, err := value.UnmarshalAPER([]byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var endpoint s09.GTPtunnelEndpoint
	if _, err := endpoint.UnmarshalAPER(make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	selected := eRABsToBeSetupRetrieveItemExtIEsExtFieldapiMust(s10.ERABsToBeSetupRetrieveItemExtIEs().ULGTPtunnelEndpoint().New(endpoint))
	cases := []struct {
		name    string
		fields  s10.ERABsToBeSetupRetrieveItemExtIEsExtContainer
		missing int
	}{
		{name: "absent"}, {name: "present empty", fields: s10.ERABsToBeSetupRetrieveItemExtIEsExtContainer{}, missing: 1}, {name: "selected mandatory", fields: s10.ERABsToBeSetupRetrieveItemExtIEsExtContainer{selected}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copy := value
			copy.IEExtensions = tc.fields
			report := s12.ValidationReport{Complete: true}
			s13.X2apInternalWalkValidationERABsToBeSetupRetrieveItem(&copy, &report, "ERABsToBeSetupRetrieveItem", false)
			missing := 0
			for _, issue := range report.Issues {
				if issue.Code == s00.MissingMandatory {
					missing++
				}
			}
			if missing != tc.missing || len(report.Issues) != tc.missing {
				t.Fatalf("mandatory count=%d, want %d: %+v", missing, tc.missing, report)
			}
		})
	}
}
