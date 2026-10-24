// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	strings "strings"
	testing "testing"
)

func portRequireRepeated(t *testing.T, report s12.ValidationReport, id s00.ProtocolIEID, index string) {
	t.Helper()
	count := 0
	for _, issue := range report.Issues {
		if issue.Code == s00.RepeatedIE && issue.IEID == id {
			count++
			if !issue.HasIEID || issue.Severity != s00.ValidationSeverityError || !strings.Contains(string(issue.Location.Path), index) {
				t.Errorf("incomplete duplicate issue: %+v", issue)
			}
			rule := false
			for _, related := range issue.RelatedRules {
				rule = rule || related.Clause == "§10.3.6"
			}
			if !rule {
				t.Errorf("missing duplicate source: %+v", issue)
			}
		}
	}
	if count != 1 {
		t.Errorf("repeated id %d issue count=%d want 1; report=%+v", id, count, report)
	}
}
