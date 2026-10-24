package lppa

import (
	q13 "bytes"
	q12 "errors"
	q11 "fmt"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

func TestReplayExtensionSpanArrayBudget(t *q8.T) {
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
	state := q10.ApplyDecodeOptions()
	bb := q10.NewBitBufferFromBytes(wire)
	if err := bb.SetDecodeOptionsAligned(state); err != nil {
		t.Fatal(err)
	}
	additions := q10.BeginExtensionAdditions(bb)
	if preamble, err := bb.ReadBits(7); err != nil || preamble != 0x40 {
		t.Fatalf("preamble=%x err=%v", preamble, err)
	}
	_, present, err := additions.DecodeBitmapAligned(bb)
	if err != nil || len(present) != 256 {
		t.Fatalf("bitmap=%d err=%v", len(present), err)
	}
	n := uint64(len(present))
	if err := q10.ChargeSlice[[]byte](bb, n); err != nil {
		t.Fatal(err)
	}
	if err := q10.ChargeSlice[q10.OpaqueOrigin](bb, n); err != nil {
		t.Fatal(err)
	}
	if err := q10.ChargeSlice[q10.WireSpan](bb, n); err != nil {
		t.Fatal(err)
	}
	arrayRequired := state.Usage().AllocatedBytes
	for _, limit := range []uint64{arrayRequired - 1, arrayRequired, arrayRequired + 1} {
		t.Run(q11.Sprintf("array-%d", limit), func(t *q8.T) {
			state := q10.ApplyDecodeOptions(q10.WithLimits(q10.Limits{MaxAllocatedBytes: limit}))
			bb := q10.NewBitBufferFromBytes(wire)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			var decoded CriticalityDiagnostics
			err := bridge0.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&decoded, bb)
			if limit < arrayRequired {
				var located *q10.DecodeError
				if !q12.Is(err, q10.ErrLimit) || !q12.As(err, &located) || !located.Location.HasWireLocation {
					t.Fatalf("array refusal=%v", err)
				}
				if *bridge0.BridgeCriticalityDiagnosticsFieldExtWire(&decoded) != nil {
					t.Fatal("extension span array allocated before reservation")
				}
			} else if len(*bridge0.BridgeCriticalityDiagnosticsFieldExtWire(&decoded)) != len(present) {
				t.Fatalf("reserved array length=%d want %d: %v", len(*bridge0.BridgeCriticalityDiagnosticsFieldExtWire(&decoded)), len(present), err)
			}
		})
	}
	opaque, err := q10.DecodeOpaqueOpenTypeAligned(bb, q10.UnknownSelector, q10.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
	if err != nil {
		t.Fatal(err)
	}
	opaque = opaque.WithPath("Extensions")
	if err := opaque.ObserveIndexed(q10.UnknownExtension, 255); err != nil {
		t.Fatal(err)
	}
	var retained q10.WireSpan
	opaque.RetainContents(&retained)
	_ = opaque.Origin()
	required := state.Usage().AllocatedBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		t.Run(q11.Sprint(limit), func(t *q8.T) {
			state := q10.ApplyDecodeOptions(q10.WithLimits(q10.Limits{MaxAllocatedBytes: limit}))
			bb := q10.NewBitBufferFromBytes(wire)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			var decoded CriticalityDiagnostics
			err := bridge0.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&decoded, bb)
			_, err = q10.FinishDecode(state, err)
			if (limit < required) != q12.Is(err, q10.ErrLimit) {
				t.Fatalf("limit=%d required=%d error=%v", limit, required, err)
			}
			if limit < required {
				var located *q10.DecodeError
				if !q12.As(err, &located) || located.Kind != q10.Limit || !located.Location.HasWireLocation || len(located.Location.Spans) == 0 {
					t.Fatalf("unlocated span-array refusal: %v", err)
				}
				return
			}
			if got := state.Usage().AllocatedBytes; got != required {
				t.Fatalf("extension storage charged %d bytes, want %d", got, required)
			}
			got, err := decoded.MarshalAPER()
			if err != nil || !q13.Equal(got, wire) {
				t.Fatalf("replay=%x want=%x err=%v", got, wire, err)
			}
		})
	}
}
func TestReplayNestedReaderOverflowBudget(t *q8.T) {
	wire := replayGrowthWire(t, 32)
	owned, state := q10.OwnDecodeInputOptions(wire)
	var baseline ECIDMeasurementInitiationRequest
	if err := bridge1.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&baseline, owned, state); err != nil {
		t.Fatal(err)
	}
	required := state.Usage().AllocatedBytes
	for _, limit := range []uint64{required - 1, required, required + 1} {
		t.Run(q11.Sprint(limit), func(t *q8.T) {
			var decoded ECIDMeasurementInitiationRequest
			owned, state := q10.OwnDecodeInputOptions(wire, q10.WithLimits(q10.Limits{MaxAllocatedBytes: limit}))
			err := bridge1.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&decoded, owned, state)
			_, err = q10.FinishDecode(state, err)
			if (limit < required) != q12.Is(err, q10.ErrLimit) {
				t.Fatalf("limit=%d required=%d error=%v", limit, required, err)
			}
			if limit < required {
				var located *q10.DecodeError
				if !q12.As(err, &located) || located.Kind != q10.Limit || !located.Location.HasWireLocation || len(located.Location.Spans) == 0 {
					t.Fatalf("unlocated complete reader refusal: %v", err)
				}
				return
			}
			got, err := decoded.MarshalAPER()
			if err != nil || !q13.Equal(got, wire) {
				t.Fatalf("replay changed: %v", err)
			}
		})
	}
}
