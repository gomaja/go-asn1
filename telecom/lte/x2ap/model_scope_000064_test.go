// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	testing "testing"
)

func TestUnboundProcedureBindingsRefuse(t *testing.T) {
	var initiating s20.ErrorIndicationInitiatingBinding
	if _, err := initiating.Build(s20.ErrorIndication{}); err == nil {
		t.Fatal("unbound initiating binding built")
	}
	if _, err := initiating.Codec().New(s20.ErrorIndication{}); err == nil {
		t.Fatal("unbound initiating codec accepted value")
	}
	var successful s19.ResetResponseSuccessfulBinding
	if _, err := successful.Build(s19.ResetResponse{}); err == nil {
		t.Fatal("unbound successful binding built")
	}
	if _, err := successful.Codec().New(s19.ResetResponse{}); err == nil {
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
