package lppa

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"reflect"
	"testing"
)

// X.691 (02/2021) §§23.8 and 11.2.1 delimit a source-known extension.
func TestRecordedTerminalPaddingChoiceOTDOACellInformationItemCrsCPlength(t *testing.T) {
	wire := []byte{0x85, 0x01, 0x3f}
	for _, receiver := range []bool{false, true} {
		options := []aper.DecodeOption{}
		if receiver {
			options = append(options, aper.WithReceiverMode())
		}
		var strict OTDOACellInformationItem
		if _, err := strict.UnmarshalAPER(wire, options...); err == nil {
			t.Fatal("accepted nonzero padding without option")
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value OTDOACellInformationItem
		report, err := value.UnmarshalAPER(wire, options...)
		if err != nil {
			t.Fatal(err)
		}
		want := aper.DecodeReport{Observations: []aper.Observation{{Kind: aper.NonzeroTerminalPadding, PaddingBits: 63, PaddingCount: 6, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "OTDOACellInformationItem.CrsCPlength", Spans: []aper.BitSpan{{Start: 18, End: 24}}, HasWireLocation: true}}}}
		if !reflect.DeepEqual(report, want) {
			t.Fatalf("report=%+v want=%+v", report, want)
		}
		if value.Choice != OTDOACellInformationItemChoiceCrsCPlength {
			t.Fatalf("lost selected alternative: %+v", value)
		}
		replay, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
	}
}
