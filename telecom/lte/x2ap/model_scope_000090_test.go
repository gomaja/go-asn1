// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestDescriptorBuildFailuresHaveOwnedIdentity(t *testing.T) {
	body, err := s20.NewErrorIndication(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func() error{
		func() error { _, err := (s20.ErrorIndicationInitiatingBinding{}).Build(body); return err },
		func() error { _, err := (ErrorIndicationSuccessfulBinding{}).Build(body); return err },
		func() error { _, err := (ErrorIndicationUnsuccessfulBinding{}).Build(body); return err },
	} {
		var located *aper.DecodeError
		err := run()
		if !errors.Is(err, aper.ErrInvalidValue) || !errors.As(err, &located) || located.Location.Path == "" || located.Location.HasWireLocation {
			t.Fatalf("build error=%v location=%+v", err, located)
		}
	}
}
