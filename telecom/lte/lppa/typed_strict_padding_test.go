package lppa

import (
	"bytes"
	"errors"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

// X.691 (02/2021) §11.1.4 applies to every complete open value (§11.2.1),
// including a known IE nested below a known procedure.
func TestStrictKnownIEPaddingAndReset(t *testing.T) {
	field, err := ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewErrorIndication(ErrorIndicationIEContainer{field})
	if err != nil {
		t.Fatal(err)
	}
	message, err := ErrorIndicationProcedure().Initiating().Build(body, 7)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := NewLPPAPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Clone(wire)
	malformed[len(malformed)-1] |= 1
	var reused LPPAPDU
	if _, err := reused.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	for _, receiver := range []*LPPAPDU{new(LPPAPDU), &reused} {
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
	var decoded LPPAPDU
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
