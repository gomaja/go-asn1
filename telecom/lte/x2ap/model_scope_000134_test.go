// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	bytes "bytes"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	reflect "reflect"
	testing "testing"
)

func TestRecordedTerminalPaddingTopLevel(t *testing.T) {
	// These X2APPDU envelopes end with an octet-aligned open type, so a named
	// complete value exercises the top-level terminal boundary directly.
	canonical := []byte{0}
	nonzero := []byte{1}
	var value s06.CriticalityDiagnostics
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
