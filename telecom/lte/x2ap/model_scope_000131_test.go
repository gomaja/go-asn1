// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	errors "errors"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

// X.691 (02/2021) §11.1.4 applies to every complete open value (§11.2.1),
// including a known IE nested below a known procedure.
func TestStrictKnownIEPaddingAndReset(t *testing.T) {
	field, err := s11.ErrorIndicationIEs().CriticalityDiagnostics().New(s06.CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s19.NewErrorIndication(s11.ErrorIndicationIEContainer{field})
	if err != nil {
		t.Fatal(err)
	}
	message, err := s19.ErrorIndicationProcedure().Initiating().Build(body)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := s20.NewX2APPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Clone(wire)
	malformed[len(malformed)-1] |= 1
	var reused s19.X2APPDU
	if _, err := reused.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	for _, receiver := range []*s19.X2APPDU{new(s19.X2APPDU), &reused} {
		_, err := receiver.UnmarshalAPER(malformed)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path == "" || located.Rule.Clause != "§11.1.4" || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 {
			t.Fatalf("nested padding error: %v, %+v", err, located)
		}
		span := located.Location.Spans[0]
		if span.Start < uint64(len(wire)-1)*8 || span.End != uint64(len(wire))*8 {
			t.Fatalf("nested location points into scratch data: %+v", located)
		}
		if receiver.Choice != 0 || receiver.InitiatingMessage != nil || receiver.ReceivedForm().Present() {
			t.Fatalf("failed decode retained receiver: %+v", receiver)
		}
	}
	var decoded s19.X2APPDU
	if _, err := decoded.UnmarshalAPER(append(bytes.Clone(wire), 0)); !errors.Is(err, aper.ErrSyntax) {
		t.Fatalf("appended top-level octet accepted: %v", err)
	}
	if _, err := decoded.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	replay, err := decoded.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("legal replay: %x %v", replay, err)
	}
}
