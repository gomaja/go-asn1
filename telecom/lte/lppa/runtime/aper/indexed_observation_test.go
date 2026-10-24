// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/indexed_observation_test.go; SHA-256 48dacdc0ccee7f4d57e81edd96d5a2b3df1ca504f5980bfd549fe643702cd41c.
package aper

import (
	"reflect"
	"testing"
)

func TestIndexedObservationPreservesStoredOrigin(t *testing.T) {
	for _, mode := range []struct {
		name    string
		options []DecodeOption
	}{
		{"strict", nil}, {"receiver", []DecodeOption{WithReceiverMode()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			state := ApplyDecodeOptions(mode.options...)
			bb := NewBitBufferFromBytes([]byte{1, 0xa5})
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
			if err != nil {
				t.Fatal(err)
			}
			raw = raw.WithPath("Extensions")
			for _, index := range []int64{0, 1, 127} {
				if err := raw.ObserveIndexed(UnknownExtension, index); err != nil {
					t.Fatal(err)
				}
			}
			report, err := FinishDecode(state, nil)
			if err != nil || len(report.Observations) != 3 {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			for i, path := range []Path{"Extensions[0]", "Extensions[1]", "Extensions[127]"} {
				observation := report.Observations[i]
				want := raw.Origin().Location
				want.Path = path
				if observation.Kind != UnknownExtension || observation.Rule != raw.Origin().Rule || !reflect.DeepEqual(observation.Location, want) {
					t.Errorf("observation=%+v, want location=%+v", observation, want)
				}
			}
			if got := raw.Origin().Location.Path; got != "Extensions" {
				t.Errorf("stored path=%q, want Extensions", got)
			}
		})
	}
}

func TestIndexedObservationWithoutReportDoesNotAllocate(t *testing.T) {
	for _, raw := range []OpaqueOpenType{
		NewOpaqueOpenType([]byte{0xa5}).WithPath("Extensions"),
		{parent: NewBitBufferFromBytes(nil), origin: OpaqueOrigin{Location: Location{Path: "Extensions"}}},
	} {
		allocations := testing.AllocsPerRun(100, func() {
			if err := raw.ObserveIndexed(UnknownExtension, 127); err != nil {
				panic(err)
			}
		})
		if allocations != 0 {
			t.Errorf("unrecorded indexed observation allocated %v times", allocations)
		}
	}
}
