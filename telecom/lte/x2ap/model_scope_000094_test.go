// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func TestEveryObservationNamesItsMember(t *testing.T) {
	check := func(report aper.DecodeReport, err error, want aper.Path) {
		t.Helper()
		if err != nil || len(report.Observations) != 1 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		observation := report.Observations[0]
		if observation.Location.Path != want || !observation.Location.HasWireLocation || len(observation.Location.Spans) == 0 || observation.Rule.Document == "" || observation.Rule.Clause == "" {
			t.Fatalf("observation=%+v want=%s", observation, want)
		}
	}
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		unknown, err := s19.NewX2APPDUUnknownExtension(7, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err := unknown.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var pdu s19.X2APPDU
		report, err := pdu.UnmarshalAPER(wire, options...)
		check(report, err, "UnknownExtension")
		cd := s06.CriticalityDiagnostics{}
		if err := cd.SetExtension(3, []byte{0}); err != nil {
			t.Fatal(err)
		}
		wire, err = cd.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var decoded s06.CriticalityDiagnostics
		report, err = decoded.UnmarshalAPER(wire, options...)
		check(report, err, "Extensions[3]")
		if report.Observations[0].Location.Path != decoded.Extensions()[0].Origin().Location.Path {
			t.Fatal("sequence view and observation disagree")
		}
		opaque, err := s19.NewOpaqueInitiatingMessage(250, s00.CriticalityIgnore, []byte{0})
		if err != nil {
			t.Fatal(err)
		}
		wire, err = opaque.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var envelope s19.InitiatingMessage
		report, err = envelope.UnmarshalAPER(wire, options...)
		check(report, err, "InitiatingMessage.Value")
		wire = receiverUnknownWire(t, 1)
		report, err = pdu.UnmarshalAPER(wire, options...)
		check(report, err, "ProtocolIEField.Value")
		_, report, err = s06.TimeToWaitCodec().DecodeAPER([]byte{0x80}, options...)
		check(report, err, "TimeToWait")
	}
}
