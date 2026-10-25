package lppa

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"reflect"
	"strings"
	"testing"
)

// Synthetic ErrorIndication values exercise every known open boundary while
// retaining typed CriticalityDiagnostics. X.691 (02/2021) §§11.1.4, 11.2.1.
func TestRecordedTerminalPaddingKnownIE(t *testing.T) {
	canonical, err := hex.DecodeString("0000400007080000010001400100")
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
		var refused LPPAPDU
		report, err := refused.UnmarshalAPER(nonzero, options...)
		var located *aper.DecodeError
		if !errors.Is(err, aper.ErrSyntax) || !errors.As(err, &located) || located.Location.Path == "" || strings.Contains(err.Error(), "at :") || len(report.Deviations) != 1 || len(report.Observations) != 0 {
			t.Fatalf("strict refusal: %+v %v", report, err)
		}
		options = append(options, aper.WithNonzeroTerminalPadding())
		var value LPPAPDU
		report, err = value.UnmarshalAPER(nonzero, options...)
		if err != nil || len(report.Observations) != 1 || len(report.Deviations) != 0 {
			t.Fatalf("recorded decode: %+v %v", report, err)
		}
		observation := report.Observations[0]
		want := aper.Observation{Kind: aper.NonzeroTerminalPadding, PaddingBits: 1, PaddingCount: 1, Rule: aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§11.2.1"}, Location: aper.Location{Path: "LPPAPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", HasWireLocation: true, Spans: []aper.BitSpan{{Start: uint64(len(nonzero))*8 - 1, End: uint64(len(nonzero)) * 8}}}}
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
		header.Criticality = CriticalityReject
		headerEdited.InitiatingMessage = &header
		headerWire, err := headerEdited.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var headerStrict LPPAPDU
		if report, err := headerStrict.UnmarshalAPER(headerWire); err != nil || len(report.Observations) != 0 {
			t.Fatalf("header edit retained nonzero child padding: %+v %v", report, err)
		}
		originalAgain, err := value.MarshalAPER()
		if err != nil || !bytes.Equal(originalAgain, nonzero) {
			t.Fatalf("edited copy changed original replay: %x %v", originalAgain, err)
		}
		// A semantic edit makes this IE's old padding ineligible for replay.
		code := ProcedureCode(0)
		diagnostics.ProcedureCode = &code
		edited, err := value.MarshalAPER()
		if err != nil {
			t.Fatal(err)
		}
		var strict LPPAPDU
		if report, err := strict.UnmarshalAPER(edited); err != nil || len(report.Observations) != 0 {
			t.Fatalf("edited encoding retained nonzero padding: %x %+v %v", edited, report, err)
		}
	}
}

func TestRecordedTerminalPaddingTwoOccurrences(t *testing.T) {
	// Repeated IEs are a separate validation matter. Wire decoding remains lossless.
	canonical, err := hex.DecodeString("0000400007080000010001400100")
	if err != nil {
		t.Fatal(err)
	}
	prefix := len(canonical) - 8
	wire := append(bytes.Clone(canonical[:prefix]), append([]byte{0, 0, 2}, append(bytes.Clone(canonical[len(canonical)-5:]), canonical[len(canonical)-5:]...)...)...)
	wire[prefix-1] = 13
	wire[len(wire)-1] |= 1
	wire[len(wire)-6] |= 1
	var value LPPAPDU
	report, err := value.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding())
	if err != nil || len(report.Observations) != 2 || len(report.Deviations) != 0 {
		t.Fatalf("two occurrences: wire=%x report=%+v error=%v", wire, report, err)
	}
	for i, observation := range report.Observations {
		end := uint64(len(wire)-5+5*i) * 8
		want := aper.Location{Path: aper.Path([]string{"LPPAPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", "LPPAPDU.InitiatingMessage.Value.ProtocolIEs[1].Value"}[i]), HasWireLocation: true, Spans: []aper.BitSpan{{Start: end - 1, End: end}}}
		if !reflect.DeepEqual(observation.Location, want) || observation.Kind != aper.NonzeroTerminalPadding || observation.PaddingCount != 1 || observation.PaddingBits != 1 || observation.Rule.Clause != "§11.2.1" {
			t.Fatalf("occurrence %d: %+v want=%+v", i, observation, want)
		}
	}
	replay, err := value.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("two-value replay=%x %v", replay, err)
	}
	var limited LPPAPDU
	report, err = limited.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding(), aper.WithLimits(aper.Limits{MaxReports: 1}))
	if !errors.Is(err, aper.ErrLimit) || len(report.Observations) != 1 || limited.InitiatingMessage != nil {
		t.Fatalf("report limit: %+v %v", report, err)
	}
}

func TestRecordedTerminalPaddingTopLevel(t *testing.T) {
	// These LPPAPDU envelopes end with an octet-aligned open type, so a named
	// complete value exercises the top-level terminal boundary directly.
	canonical := []byte{0}
	nonzero := []byte{1}
	var value CriticalityDiagnostics
	report, err := value.UnmarshalAPER(nonzero, aper.WithNonzeroTerminalPadding())
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("top-level decode: %+v %v", report, err)
	}
	observation := report.Observations[0]
	if observation.Kind != aper.NonzeroTerminalPadding || observation.Location.Path != "CriticalityDiagnostics" || observation.Rule.Clause != "§11.1.4" || observation.PaddingCount != 1 || observation.PaddingBits != 1 || !reflect.DeepEqual(observation.Location.Spans, []aper.BitSpan{{Start: 8 - 1, End: 8}}) {
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
