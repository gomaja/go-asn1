// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	testing "testing"
)

// X.691 (02/2021) §§23.6–23.8 encode only the chosen alternative.
// The TS 36.423 V19.1.0 §9.3.5 extension tables belong to that value alone.
func TestNestedValidationIgnoresInactiveChoiceArms(t *testing.T) {
	bad := lastVisitedEUTRANCellInformationExtIEsExtFieldapiMust(s16.LastVisitedEUTRANCellInformationExtIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0}))
	bad.Id--
	inactive := s16.LastVisitedEUTRANCellInformation{IEExtensions: s16.LastVisitedEUTRANCellInformationExtIEsExtContainer{bad}}
	active := s00.LastVisitedUTRANCellInformation{}
	value := s16.LastVisitedCellItem{Choice: s00.LastVisitedCellItemChoiceUTRANCell, UTRANCell: &active, EUTRANCell: &inactive}
	if _, err := value.MarshalAPER(); err != nil {
		t.Fatal(err)
	}
	report := s12.ValidationReport{Complete: true}
	s16.X2apInternalWalkValidationLastVisitedCellItem(&value, &report, "LastVisitedCellItem", false)
	if len(report.Issues) != 0 || len(report.Deferred) != 0 || len(report.Unchecked) != 0 || !report.Complete {
		t.Fatalf("inactive EUTRAN arm contaminated selected UTRAN report: %+v", report)
	}
	// The exact same pointer is validated when its discriminator is selected.
	value.Choice = s00.LastVisitedCellItemChoiceEUTRANCell
	report = s12.ValidationReport{Complete: true}
	s16.X2apInternalWalkValidationLastVisitedCellItem(&value, &report, "LastVisitedCellItem", false)
	apiHas(t, report, s00.ValueIDMismatch)
}
