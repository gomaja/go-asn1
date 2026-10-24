package lppa

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

func TestReplayExtensionSpanArrayBudget(t *testing.T) {
	var source CriticalityDiagnostics
	if err := source.SetExtension(255, []byte{0x80}); err != nil {
		t.Fatal(err)
	}
	wire, err := source.MarshalAPER()
	if err != nil {
		t.Fatal(err)
	}
	// An independent walk accounts for each retained backing array, including
	// one WireSpan for every bitmap position, before reading the open type.
	state := aper.ApplyDecodeOptions()
	bb := aper.NewBitBufferFromBytes(wire)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	additions := aper.BeginExtensionAdditions(bb)
	if preamble, err := bb.ReadBits(7); err != nil || preamble != 0x40 {
		t.Fatalf("preamble=%x err=%v", preamble, err)
	}
	_, present, err := additions.DecodeBitmapAligned(bb)
	if err != nil || len(present) != 256 {
		t.Fatalf("bitmap=%d err=%v", len(present), err)
	}
	n := uint64(len(present))
	if err := aper.ChargeSlice[[]byte](bb, n); err != nil {
		t.Fatal(err)
	}
	if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, n); err != nil {
		t.Fatal(err)
	}
	if err := aper.ChargeSlice[aper.WireSpan](bb, n); err != nil {
		t.Fatal(err)
	}
	arrayRequired := state.Usage().AllocatedBytes
	for _, limit := range []uint64{arrayRequired - 1, arrayRequired, arrayRequired + 1} {
		t.Run(fmt.Sprintf("array-%d", limit), func(t *testing.T) {
			state := aper.ApplyDecodeOptions(aper.WithLimits(aper.Limits{MaxAllocatedBytes: limit}))
			bb := aper.NewBitBufferFromBytes(wire)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			var decoded CriticalityDiagnostics
			err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&decoded, bb)
			if limit < arrayRequired {
				var located *aper.DecodeError
				if !errors.Is(err, aper.ErrLimit) || !errors.As(err, &located) || !located.Location.HasWireLocation {
					t.Fatalf("array refusal=%v", err)
				}
				if *s09.BridgeCriticalityDiagnosticsFieldExtWire(&decoded) != nil {
					t.Fatal("extension span array allocated before reservation")
				}
			} else if len(*s09.BridgeCriticalityDiagnosticsFieldExtWire(&decoded)) != len(present) {
				t.Fatalf("reserved array length=%d want %d: %v", len(*s09.BridgeCriticalityDiagnosticsFieldExtWire(&decoded)), len(present), err)
			}
		})
	}
	opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	opaque = opaque.WithPath("Extensions")
	if err := opaque.ObserveIndexed(aper.UnknownExtension, 255); err != nil {
		t.Fatal(err)
	}
	var retained aper.WireSpan
	opaque.RetainContents(&retained)
	_ = opaque.Origin()
	required := state.Usage().AllocatedBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			state := aper.ApplyDecodeOptions(aper.WithLimits(aper.Limits{MaxAllocatedBytes: limit}))
			bb := aper.NewBitBufferFromBytes(wire)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			var decoded CriticalityDiagnostics
			err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&decoded, bb)
			_, err = aper.FinishDecode(state, err)
			if (limit < required) != errors.Is(err, aper.ErrLimit) {
				t.Fatalf("limit=%d required=%d error=%v", limit, required, err)
			}
			if limit < required {
				var located *aper.DecodeError
				if !errors.As(err, &located) || located.Kind != aper.Limit || !located.Location.HasWireLocation || len(located.Location.Spans) == 0 {
					t.Fatalf("unlocated span-array refusal: %v", err)
				}
				return
			}
			if got := state.Usage().AllocatedBytes; got != required {
				t.Fatalf("extension storage charged %d bytes, want %d", got, required)
			}
			got, err := decoded.MarshalAPER()
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("replay=%x want=%x err=%v", got, wire, err)
			}
		})
	}
}
func TestReplayNestedReaderOverflowBudget(t *testing.T) {
	wire := replayGrowthWire(t, 32)
	owned, state := aper.OwnDecodeInputOptions(wire)
	var baseline ECIDMeasurementInitiationRequest
	if err := s21.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&baseline, owned, state); err != nil {
		t.Fatal(err)
	}
	required := state.Usage().AllocatedBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var decoded ECIDMeasurementInitiationRequest
			owned, state := aper.OwnDecodeInputOptions(wire, aper.WithLimits(aper.Limits{MaxAllocatedBytes: limit}))
			err := s21.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&decoded, owned, state)
			_, err = aper.FinishDecode(state, err)
			if (limit < required) != errors.Is(err, aper.ErrLimit) {
				t.Fatalf("limit=%d required=%d error=%v", limit, required, err)
			}
			if limit < required {
				var located *aper.DecodeError
				if !errors.As(err, &located) || located.Kind != aper.Limit || !located.Location.HasWireLocation || len(located.Location.Spans) == 0 {
					t.Fatalf("unlocated complete reader refusal: %v", err)
				}
				return
			}
			got, err := decoded.MarshalAPER()
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("replay changed: %v", err)
			}
		})
	}
}
