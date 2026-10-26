// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	testing "testing"
)

func apiHas(t *testing.T, r s12.ValidationReport, code s00.ValidationCode) {
	t.Helper()
	for _, issue := range r.Issues {
		if issue.Code == code {
			if issue.Rule.Document != "3GPP TS 36.423" || issue.Rule.Clause != "§10" || issue.Location.Path == "" {
				t.Errorf("unlocated or unsourced issue: %+v", issue)
			}
			return
		}
	}
	t.Errorf("missing issue %d: %+v", code, r)
}
