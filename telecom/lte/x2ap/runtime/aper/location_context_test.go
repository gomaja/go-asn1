// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/location_context_test.go; SHA-256 fe4e5a1890aac738e686891f164840c3f8bf4adc0c403a1470f813e94b735f20.
package aper_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

func TestLocatedErrorRetainsInnerPathAcrossProcedureContext(t *testing.T) {
	original := &aper.DecodeError{Kind: aper.Syntax, Location: aper.Location{Spans: []aper.BitSpan{{Start: 19, End: 24}}, HasWireLocation: true}, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.1.4"}, Err: aper.ErrInvalidValue}
	inner := runtime.WrapDecodePath(runtime.WrapDecodePath(original, "Value"), "ProtocolIEs[3]")
	err := runtime.WrapDecodePath(fmt.Errorf("known procedure body: %w", inner), "Envelope")
	var located *aper.DecodeError
	if !errors.As(err, &located) || located.Location.Path != "Envelope.ProtocolIEs[3].Value" || located.Rule != original.Rule || len(located.Location.Spans) != 1 || located.Location.Spans[0] != original.Location.Spans[0] {
		t.Fatalf("lost deepest path/rule: %v / %+v", err, located)
	}
	if original.Location.Path != "" {
		t.Fatal("ancestor changed the original occurrence")
	}
}
