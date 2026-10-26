// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestZeroKnownTableValueIsInvalid(t *testing.T) {
	field := s09.ERABsAdmittedItemIEField{Id: 0, Criticality: s00.CriticalityIgnore}
	bb := aper.NewBitBuffer()
	apiRefused(t, s09.X2apInternalERABsAdmittedItemIEFieldMarshalAPERTo(&field, bb))
	if bb.BitPos() != 0 {
		t.Fatal("invalid zero table value emitted field bits")
	}
	list := s11.ERABsAdmittedList{field}
	report := s12.ValidationReport{Complete: true}
	s13.X2apInternalWalkValidationERABsAdmittedList(&list, &report, "ERABsAdmittedList", false)
	apiHas(t, report, s00.ValueIDMismatch)
}
