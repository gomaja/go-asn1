// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func FuzzAPERX2APPDUReceiverNonzeroTerminalPadding(f *testing.F) {
	f.Add(asn1VectorHexForFuzz("002e0002bbcc"))
	f.Fuzz(func(t *testing.T, input []byte) {
		var decoded s19.X2APPDU
		report, err := decoded.UnmarshalAPER(input, aper.WithNonzeroTerminalPadding(), aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, report, input, false)
		if err != nil {
			return
		}
		replay, err := decoded.MarshalAPER()
		if err != nil {
			t.Fatalf("accepted input cannot replay: %v", err)
		}
		if !bytes.Equal(replay, input) {
			t.Fatalf("replay = %x, want %x", replay, input)
		}
		fresh, err := decoded.MarshalAPER(aper.WithoutReplay())
		if err != nil {
			t.Fatalf("fresh encode: %v", err)
		}
		var again s19.X2APPDU
		freshReport, err := again.UnmarshalAPER(fresh, aper.WithReceiverMode())
		asn1VectorCheckPaddingReport(t, freshReport, fresh, true)
		if err != nil {
			t.Fatalf("fresh decode: %v", err)
		}
	})
}
