// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	hex "encoding/hex"
	errors "errors"
	s20 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s20"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	reflect "reflect"
	testing "testing"
)

func TestRecordedTerminalPaddingTwoOccurrences(t *testing.T) {
	// Repeated IEs are a separate validation matter. Wire decoding remains lossless.
	canonical, err := hex.DecodeString("000340080000010011400100")
	if err != nil {
		t.Fatal(err)
	}
	prefix := len(canonical) - 8
	wire := append(bytes.Clone(canonical[:prefix]), append([]byte{0, 0, 2}, append(bytes.Clone(canonical[len(canonical)-5:]), canonical[len(canonical)-5:]...)...)...)
	wire[prefix-1] = 13
	wire[len(wire)-1] |= 1
	wire[len(wire)-6] |= 1
	var value s20.X2APPDU
	report, err := value.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding())
	if err != nil || len(report.Observations) != 2 || len(report.Deviations) != 0 {
		t.Fatalf("two occurrences: wire=%x report=%+v error=%v", wire, report, err)
	}
	for i, observation := range report.Observations {
		end := uint64(len(wire)-5+5*i) * 8
		want := aper.Location{Path: aper.Path([]string{"X2APPDU.InitiatingMessage.Value.ProtocolIEs[0].Value", "X2APPDU.InitiatingMessage.Value.ProtocolIEs[1].Value"}[i]), HasWireLocation: true, Spans: []aper.BitSpan{{Start: end - 2, End: end}}}
		if !reflect.DeepEqual(observation.Location, want) || observation.Kind != aper.NonzeroTerminalPadding || observation.PaddingCount != 2 || observation.PaddingBits != 1 || observation.Rule.Clause != "§11.2.1" {
			t.Fatalf("occurrence %d: %+v want=%+v", i, observation, want)
		}
	}
	replay, err := value.MarshalAPER()
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("two-value replay=%x %v", replay, err)
	}
	var limited s20.X2APPDU
	report, err = limited.UnmarshalAPER(wire, aper.WithNonzeroTerminalPadding(), aper.WithLimits(aper.Limits{MaxReports: 1}))
	if !errors.Is(err, aper.ErrLimit) || len(report.Observations) != 1 || limited.InitiatingMessage != nil {
		t.Fatalf("report limit: %+v %v", report, err)
	}
}
