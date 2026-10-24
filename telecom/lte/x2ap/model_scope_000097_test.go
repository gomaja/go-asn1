// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	strings "strings"
	testing "testing"
)

func TestKnownChoicePaddingFailureHasOneOriginalLocation(t *testing.T) {
	known, err := s00.NewENBIDShortMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 18})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := known.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] |= 1
	for _, options := range [][]aper.DecodeOption{nil, {aper.WithReceiverMode()}} {
		var value s00.ENBID
		report, err := value.UnmarshalAPER(wire, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || len(report.Deviations) != 1 || len(report.Observations) != 0 || !located.Location.HasWireLocation || len(located.Location.Spans) != 1 || located.Rule.Clause != "§11.1.4" || !strings.Contains(string(located.Location.Path), "ShortMacroENBID") {
			t.Fatalf("known choice report=%+v err=%v location=%+v", report, err, located)
		}
		span := located.Location.Spans[0]
		if span.End != uint64(len(wire))*8 || span.Start != span.End-6 {
			t.Fatalf("known choice span=%+v", span)
		}
	}
}
