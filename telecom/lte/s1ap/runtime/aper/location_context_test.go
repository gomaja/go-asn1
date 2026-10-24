// Code generated from S1AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/location_context_test.go; SHA-256 79c0cb02c288ff2bb1e6a65f22381cf6777a06382bb86334990175aa9a5bceda.
package aper_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
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
