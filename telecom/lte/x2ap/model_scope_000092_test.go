// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestZeroUnionMatchesNoRow(t *testing.T) {
	budget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	if s18.X2apInternalHandoverRequestIEValueMatchesID((s18.HandoverRequestIEValue{}), 0, budget) {
		t.Fatal("a zero union matched id zero without an arm")
	}
}
