// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	reflect "reflect"
	testing "testing"
)

// X.691 (02/2021) §§23.8 and 11.2.1 delimit a source-known extension.
func TestRecordedTerminalPaddingChoiceENBIDShortMacroENBID(t *testing.T) {
	wire := []byte{0x80, 0x03, 0x00, 0x00, 0x3f}
	for _, receiver := range []bool{false, true} {
		options := []aper.DecodeOption{}
		if receiver {
			options = append(options, aper.WithReceiverMode())
		}
		var strict s00.ENBID
		if _, err := strict.UnmarshalAPER(wire, options...); err == nil {
			t.Fatal("accepted nonzero padding without option")
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value s00.ENBID
		report, err := value.UnmarshalAPER(wire, options...)
		if err != nil {
			t.Fatal(err)
		}
		want := aper.DecodeReport{Observations: []aper.Observation{{Kind: aper.NonzeroTerminalPadding, PaddingBits: 63, PaddingCount: 6, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "ENBID.ShortMacroENBID", Spans: []aper.BitSpan{{Start: 34, End: 40}}, HasWireLocation: true}}}}
		if !reflect.DeepEqual(report, want) {
			t.Fatalf("report=%+v want=%+v", report, want)
		}
		if value.Choice != s00.ENBIDChoiceShortMacroENBID {
			t.Fatalf("lost selected alternative: %+v", value)
		}
		replay, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
	}
}
