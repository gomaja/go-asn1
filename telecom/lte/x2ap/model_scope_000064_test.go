// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	testing "testing"
)

func TestUnboundProcedureBindingsRefuse(t *testing.T) {
	var initiating s19.ErrorIndicationInitiatingBinding
	if _, err := initiating.Build(s19.ErrorIndication{}); err == nil {
		t.Fatal("unbound initiating binding built")
	}
	if _, err := initiating.Codec().New(s19.ErrorIndication{}); err == nil {
		t.Fatal("unbound initiating codec accepted value")
	}
	var successful s18.ResetResponseSuccessfulBinding
	if _, err := successful.Build(s18.ResetResponse{}); err == nil {
		t.Fatal("unbound successful binding built")
	}
	if _, err := successful.Codec().New(s18.ResetResponse{}); err == nil {
		t.Fatal("unbound successful codec accepted value")
	}
	var unsuccessful s14.X2SetupFailureUnsuccessfulBinding
	if _, err := unsuccessful.Build(s14.X2SetupFailure{}); err == nil {
		t.Fatal("unbound unsuccessful binding built")
	}
	if _, err := unsuccessful.Codec().New(s14.X2SetupFailure{}); err == nil {
		t.Fatal("unbound unsuccessful codec accepted value")
	}
}
