// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	errors "errors"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

// A CHOICE constructor creates a private pointer to its selected arm before
// validating it. That semantic copy belongs to the same build operation.
func TestChoiceBuilderReservesSelectedArmBeforeValidation(t *testing.T) {
	budget, err := aper.BuildBudget()
	if err != nil {
		t.Fatal(err)
	}
	metadata := aper.NewBudgetBuffer(budget).Usage().AllocatedBytes
	options := []aper.BuildOption{aper.WithBuildLimits(aper.Limits{MaxAllocatedBytes: metadata})}
	for _, test := range []struct {
		name  string
		build func() error
	}{
		{"known arm", func() error {
			_, err := s52.NewS1APPDUInitiatingMessage(s51.InitiatingMessage{}, options...)
			return err
		}},
		{"unknown holder", func() error { _, err := s52.NewS1APPDUUnknownExtension(0, nil, options...); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.build()
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || located.Location.HasWireLocation || located.Location.Path == "" {
				t.Fatalf("selected arm copied without reserving storage: error=%v location=%+v", err, located)
			}
		})
	}
}
