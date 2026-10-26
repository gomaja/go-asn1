// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	errors "errors"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	reflect "reflect"
	strings "strings"
	testing "testing"
)

// X.691 (02/2021) §11.1.4 applies to every complete open value (§11.2.1),
// including a known IE nested below a known procedure.
func TestStrictKnownIEPaddingAndReset(t *testing.T) {
	field, err := s36.ErrorIndicationIEs().CriticalityDiagnostics().New(s26.CriticalityDiagnostics{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := s62.NewErrorIndication(s36.ErrorIndicationIEContainer{field})
	if err != nil {
		t.Fatal(err)
	}
	message, err := s65.ErrorIndicationProcedure().Initiating().Build(body)
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := s67.NewS1APPDUInitiatingMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := pdu.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	malformed := bytes.Clone(wire)
	malformed[len(malformed)-1] |= 1
	var reused s66.S1APPDU
	if _, err := reused.UnmarshalAPER(wire); err != nil {
		t.Fatal(err)
	}
	for _, receiver := range []*s66.S1APPDU{new(s66.S1APPDU), &reused} {
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
	var decoded s66.S1APPDU
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

// Synthetic ErrorIndication values exercise every known open boundary while
// retaining typed CriticalityDiagnostics. X.691 (02/2021) §§11.1.4, 11.2.1.
func TestRecordedTerminalPaddingKnownIE(t *testing.T) {
	canonical, err := hex.DecodeString("000f4008000001003a400100")
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
		var refused s66.S1APPDU
		report, err := refused.UnmarshalAPER(nonzero, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path == "" || strings.Contains(err.Error(), "at :") || len(report.Deviations) != 1 || len(report.Observations) != 0 {
			t.Fatalf("strict refusal: %+v %v", report, err)
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value s66.S1APPDU
		report, err = value.UnmarshalAPER(nonzero, options...)
		if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("recorded decode: %+v %v", report, err)
		}
		observation := report.Observations[0]
		want := aper.Observation{Kind: aper.NonzeroTerminalPadding, PaddingBits: 1, PaddingCount: 2, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "S1APPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", HasWireLocation: true, Spans: []aper.BitSpan{{Start: uint64(len(nonzero))*8 - 2, End: uint64(len(nonzero)) * 8}}}}
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
		var headerStrict s66.S1APPDU
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
		var strict s66.S1APPDU
		if report, err := strict.UnmarshalAPER(edited); err != nil || len(report.Observations) != 0 {
			t.Fatalf("edited encoding retained nonzero padding: %x %+v %v", edited, report, err)
		}
	}
}
func TestRecordedTerminalPaddingTwoOccurrences(t *testing.T) {
	// Repeated IEs are a separate validation matter. Wire decoding remains lossless.
	canonical, err := hex.DecodeString("000f4008000001003a400100")
	if err != nil {
		t.Fatal(err)
	}
	prefix := len(canonical) - 8
	wire := append(bytes.Clone(canonical[:prefix]), append([]byte{0, 0, 2}, append(bytes.Clone(canonical[len(canonical)-5:]), canonical[len(canonical)-5:]...)...)...)
	wire[prefix-1] = 13
	wire[len(wire)-1] |= 1
	wire[len(wire)-6] |= 1
	var value s66.S1APPDU
	report, err := value.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding())
	if err != nil || len(report.Observations) != 2 || len(report.Deviations) != 0 {
		t.Fatalf("two occurrences: wire=%x report=%+v error=%v", wire, report, err)
	}
	for i, observation := range report.Observations {
		end := uint64(len(wire)-5+5*i) * 8
		want := aper.Location{Path: aper.Path([]string{"S1APPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", "S1APPDU.InitiatingMessage.Value.ProtocolIEs[1].Value"}[i]), HasWireLocation: true, Spans: []aper.BitSpan{{Start: end - 2, End: end}}}
		if !reflect.DeepEqual(observation.Location, want) || observation.Kind != aper.NonzeroTerminalPadding || observation.PaddingCount != 2 || observation.PaddingBits != 1 || observation.Rule.Clause != "§11.2.1" {
			t.Fatalf("occurrence %d: %+v want=%+v", i, observation, want)
		}
	}
	replay, err := value.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("two-value replay=%x %v", replay, err)
	}
	var limited s66.S1APPDU
	report, err = limited.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding(), aper.WithLimits(aper.Limits{MaxReports: 1}))
	if !errors.Is(err, aper.ErrLimit) || len(report.Observations) != 1 || limited.InitiatingMessage != nil {
		t.Fatalf("report limit: %+v %v", report, err)
	}
}
func TestRecordedTerminalPaddingTopLevel(t *testing.T) {
	// These S1APPDU envelopes end with an octet-aligned open type, so a named
	// complete value exercises the top-level terminal boundary directly.
	canonical := []byte{0}
	nonzero := []byte{1}
	var value s26.CriticalityDiagnostics
	report, err := value.UnmarshalAPER(nonzero, aper.WithNonzeroTerminalPadding())
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("top-level decode: %+v %v", report, err)
	}
	observation := report.Observations[0]
	if observation.Kind != aper.NonzeroTerminalPadding || observation.Location.Path != "CriticalityDiagnostics" || observation.Rule.Clause != "§11.1.4" || observation.PaddingCount != 2 || observation.PaddingBits != 1 || !reflect.DeepEqual(observation.Location.Spans, []aper.BitSpan{{Start: 8 - 2, End: 8}}) {
		t.Fatalf("top-level observation=%+v", observation)
	}
	replay, err := value.MarshalAPER()
	if err != nil || !bytes.Equal(replay, nonzero) {
		t.Fatalf("top-level replay=%x %v", replay, err)
	}
	fresh, err := value.MarshalAPER(aper.WithoutReplay())
	if err != nil || !bytes.Equal(fresh, canonical) {
		t.Fatalf("top-level fresh=%x %v", fresh, err)
	}
}

// X.691 (02/2021) §§23.8 and 11.2.1 delimit a source-known extension.
func TestRecordedTerminalPaddingChoiceENBIDShortMacroENBID(t *testing.T) {
	wire := []byte{0x80, 0x03, 0x00, 0x00, 0x3f}
	for _, receiver := range []bool{false, true} {
		options := []aper.DecodeOption{}
		if receiver {
			options = append(options, aper.WithReceiverMode())
		}
		var strict s18.ENBID
		if _, err := strict.UnmarshalAPER(wire, options...); err == nil {
			t.Fatal("accepted nonzero padding without option")
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value s18.ENBID
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

// X.691 (02/2021) §§23.8 and 11.2.1 delimit a source-known extension.
func TestRecordedTerminalPaddingChoiceSONtransferResponseContainerHOReporting(t *testing.T) {
	wire := []byte{0x82, 0x01, 0xff}
	for _, receiver := range []bool{false, true} {
		options := []aper.DecodeOption{}
		if receiver {
			options = append(options, aper.WithReceiverMode())
		}
		var strict s28.SONtransferResponseContainer
		if _, err := strict.UnmarshalAPER(wire, options...); err == nil {
			t.Fatal("accepted nonzero padding without option")
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value s28.SONtransferResponseContainer
		report, err := value.UnmarshalAPER(wire, options...)
		if err != nil {
			t.Fatal(err)
		}
		want := aper.DecodeReport{Observations: []aper.Observation{{Kind: aper.NonzeroEmptyEncoding, PaddingBits: 255, PaddingCount: 8, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "SONtransferResponseContainer.HOReporting", Spans: []aper.BitSpan{{Start: 16, End: 24}}, HasWireLocation: true}}}}
		if !reflect.DeepEqual(report, want) {
			t.Fatalf("report=%+v want=%+v", report, want)
		}
		if value.Choice != s00.SONtransferResponseContainerChoiceHOReporting {
			t.Fatalf("lost selected alternative: %+v", value)
		}
		replay, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(replay, wire) {
			t.Fatalf("replay=%x err=%v", replay, err)
		}
	}
}
