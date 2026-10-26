// Code generated from the locked X2AP source closure. DO NOT EDIT.

package x2ap

import (
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
	testing "testing"
)

func asn1VectorCheckPaddingReport(t *testing.T, report aper.DecodeReport, input []byte, fresh bool) {
	t.Helper()
	for _, observation := range report.Observations {
		switch observation.Kind {
		case aper.NonzeroTerminalPadding, aper.NonzeroEmptyEncoding:
			if fresh {
				t.Fatalf("fresh encoding has padding observation: %+v", observation)
			}
			count := observation.PaddingCount
			if count == 0 || count > 8 || (observation.Kind == aper.NonzeroTerminalPadding && count > 7) || (observation.Kind == aper.NonzeroEmptyEncoding && count != 8) {
				t.Fatalf("invalid padding width: %+v", observation)
			}
			if observation.PaddingBits == 0 || uint16(observation.PaddingBits) >= uint16(1)<<count {
				t.Fatalf("invalid padding bits: %+v", observation)
			}
		case aper.UnknownProcedure, aper.UnknownIE, aper.UnknownExtension:
			if observation.PaddingBits != 0 || observation.PaddingCount != 0 {
				t.Fatalf("non-padding observation carries padding: %+v", observation)
			}
		default:
			t.Fatalf("unknown observation kind: %+v", observation)
		}
		if observation.Location.Path == "" {
			t.Fatalf("observation has empty path: %+v", observation)
		}
		if observation.Location.HasWireLocation {
			if len(observation.Location.Spans) == 0 {
				t.Fatalf("located observation has no spans: %+v", observation)
			}
			for _, span := range observation.Location.Spans {
				if span.Start > span.End || span.End > uint64(len(input))*8 {
					t.Fatalf("observation span outside input: %+v", observation)
				}
			}
		}
	}
}
