// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	strings "strings"
	testing "testing"
)

// TS 36.423 V19.1.0 §10 adopts TS 36.413 V19.2.0 §§10.1–10.3:
// unknown identifiers are preserved; a known malformed value is a fatal error.
func TestReceiverModeReportsAndAtomicReuse(t *testing.T) {
	unknown, err := s11.ErrorIndicationIEs().NewOpaque(65532, s00.CriticalityIgnore, []byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	known, err := s11.ErrorIndicationIEs().CriticalityDiagnostics().New(s06.CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s19.NewErrorIndication(s11.ErrorIndicationIEContainer{unknown, known})
	if err != nil {
		t.Fatal(err)
	}
	message, err := s19.ErrorIndicationProcedure().Initiating().Build(body)
	if err != nil {
		t.Fatal(err)
	}
	value, err := s20.NewX2APPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := value.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var reused s19.X2APPDU
		for range 2 {
			report, err := reused.UnmarshalAPER(wire, options...)
			if err != nil || len(report.Deviations) != 0 || len(report.Observations) != 1 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			observation := report.Observations[0]
			if observation.Kind != aper.UnknownIE || observation.Location.Path == "" || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 || observation.Rule.Document != "3GPP TS 36.423" {
				t.Fatalf("observation=%+v", observation)
			}
			replay, err := reused.MarshalAPER()
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("replay=%x err=%v", replay, err)
			}
			malformed := bytes.Clone(wire)
			malformed[len(malformed)-1] |= 1
			report, err = reused.UnmarshalAPER(malformed, options...)
			var located *aper.DecodeError
			if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || len(report.Observations) != 1 || len(report.Deviations) != 1 {
				t.Fatalf("failed report=%+v err=%v", report, err)
			}
			if report.Deviations[0].Rule != located.Rule || report.Deviations[0].Location.Path != located.Location.Path || !strings.Contains(string(located.Location.Path), "ProtocolIEs[1].Value") {
				t.Fatalf("duplicate or wrong occurrence: %+v / %+v", report, located)
			}
			if reused.Choice != 0 || reused.ReceivedForm().Present() {
				t.Fatalf("failed value retained: %+v", reused)
			}
		}
		codecValue, report, err := s19.X2APPDUCodec().DecodeAPER(wire, options...)
		if err != nil || len(report.Observations) != 1 {
			t.Fatalf("codec report=%+v err=%v", report, err)
		}
		replay, err := s19.X2APPDUCodec().EncodeAPER(codecValue)
		if err != nil || !bytes.Equal(wire, replay) {
			t.Fatalf("codec replay=%x err=%v", replay, err)
		}
	}
}
