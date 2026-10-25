// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	hex "encoding/hex"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

// Synthetic ErrorIndication values exercise every known open boundary while
// retaining typed CriticalityDiagnostics. X.691 (02/2021) §§11.1.4, 11.2.1.
func TestRecordedTerminalPaddingKnownIE(t *testing.T) {
	canonical, err := hex.DecodeString("000340080000010011400100")
	if err != nil {
		t.Fatal(err)
	}
	nonzero := bytes.Clone(canonical)
	nonzero[len(nonzero)-1] |= 1
	for _, receiver := range []bool{false, true} {
		options := []aper.DecodeOption{}
		if receiver {
			options = append(options, aper.WithReceiverMode())
		}
		var refused s20.X2APPDU
		report, err := refused.UnmarshalAPER(nonzero, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path == "" || strings.Contains(err.Error(), "at :") || len(report.Deviations) != 1 || len(report.Observations) != 0 {
			t.Fatalf("strict refusal: %+v %v", report, err)
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value s20.X2APPDU
		report, err = value.UnmarshalAPER(nonzero, options...)
		if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("recorded decode: %+v %v", report, err)
		}
		observation := report.Observations[0]
		want := aper.Observation{Kind: aper.NonzeroTerminalPadding, PaddingBits: 1, PaddingCount: 2, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "X2APPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", HasWireLocation: true, Spans: []aper.BitSpan{{Start: uint64(len(nonzero))*8 - 2, End: uint64(len(nonzero)) * 8}}}}
		if !reflect.DeepEqual(observation, want) {
			t.Fatalf("observation=%+v want=%+v", observation, want)
		}
		body, ok := value.InitiatingMessage.Value.AsErrorIndication()
		if !ok || body == nil || len(body.ProtocolIEs) != 1 {
			t.Fatal("typed body lost")
		}
		diagnostics, ok := body.ProtocolIEs[0].Value.AsCriticalityDiagnostics()
		if !ok || diagnostics == nil {
			t.Fatal("typed IE lost")
		}
		replay, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(replay, nonzero) {
			t.Fatalf("replay=%x error=%v", replay, err)
		}
		fresh, err := value.MarshalAPER(aper.WithoutReplay())
		if err != nil || !bytes.Equal(fresh, canonical) {
			t.Fatalf("fresh=%x error=%v", fresh, err)
		}
		detached := value.WithoutReplay()
		fresh, err = detached.MarshalAPER()
		if err != nil || !bytes.Equal(fresh, canonical) {
			t.Fatalf("method fresh=%x error=%v", fresh, err)
		}
		// A header edit also invalidates tolerated padding in unchanged known children.
		headerEdited := value
		header := *value.InitiatingMessage
		header.Criticality = s00.CriticalityReject
		headerEdited.InitiatingMessage = &header
		headerWire, err := headerEdited.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var headerStrict s20.X2APPDU
		if report, err := headerStrict.UnmarshalAPER(headerWire); err != nil || len(report.Observations) != 0 {
			t.Fatalf("header edit retained nonzero child padding: %+v %v", report, err)
		}
		originalAgain, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(originalAgain, nonzero) {
			t.Fatalf("edited copy changed original replay: %x %v", originalAgain, err)
		}
		// A semantic edit makes this IE's old padding ineligible for replay.
		code := s00.ProcedureCode(0)
		diagnostics.ProcedureCode = &code
		edited, err := value.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var strict s20.X2APPDU
		if report, err := strict.UnmarshalAPER(edited); err != nil || len(report.Observations) != 0 {
			t.Fatalf("edited encoding retained nonzero padding: %x %+v %v", edited, report, err)
		}
	}
}
