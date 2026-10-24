package lppa

import (
	stdhex "encoding/hex"
	"errors"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"runtime"
	"testing"
	"unsafe"
)

func TestReplaySmallMessageStorage(t *testing.T) {
	for _, row := range []struct {
		hex   string
		bytes uint64
	}{
		{"000040000003000000", 1920},
		{"0002000000080000010002000100", 2560},
		{"00020000010d00000200020001300003000140", 5120},
	} {
		wire, err := stdhex.DecodeString(row.hex)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range 100 {
			var v LPPAPDU
			if _, err := v.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			replayDecodeSink = v
		}
		runtime.ReadMemStats(&after)
		got := (after.TotalAlloc - before.TotalAlloc) / 100
		t.Logf("input=%d bytes/op=%d ceiling=%d", len(wire), got, row.bytes)
		if got > row.bytes {
			t.Errorf("input=%d allocated %d bytes/op, want at most %d", len(wire), got, row.bytes)
		}
	}
}
func TestReplayKnownUnionStorageBudget(t *testing.T) {
	if got := unsafe.Sizeof(InitiatingValue{}); got > 256 {
		t.Errorf("known procedure union uses %d bytes, want at most 256", got)
	}
	if got := unsafe.Sizeof(ECIDMeasurementInitiationRequestIEValue{}); got > 256 {
		t.Errorf("known IE union uses %d bytes, want at most 256", got)
	}
}
func TestReplayProcedureScopeLimitKeepsChildOrigin(t *testing.T) {
	wire, state := aper.OwnDecodeInputOptions([]byte{3, 0, 0, 0})
	bb := aper.NewCompleteDecodeBuffer(wire, state)
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	for range aper.DefaultLimits().MaxDepth {
		if err := bb.EnterOpenType(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s21.BridgeDecodeInitiatingValue(0, raw)
	var located *aper.DecodeError
	if !errors.As(err, &located) || located.Kind != aper.Limit || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (aper.BitSpan{Start: 8, End: 8}) {
		t.Fatalf("selected child scope lost its original start: %v", err)
	}
}
func TestReplayNamedListScopesAreIndependent(t *testing.T) {
	first, second := make(ResultNR, 1), make(ResultNR, 1)
	capture := aper.NewSemanticCapture(1024)
	frame := capture.Begin()
	s19.BridgeCaptureLPPaResultNR(&first, &capture)
	s19.BridgeCaptureLPPaResultNR(&second, &capture)
	var root aper.Snapshot
	capture.End(frame, &root, false)
	budget, err := aper.EncodeBudget(aper.WithEncodeLimits(aper.Limits{MaxDepth: 2}))
	if err != nil {
		t.Fatal(err)
	}
	comparison := aper.NewSemanticComparison(root, aper.ComparisonBudget(budget))
	current := comparison.Begin()
	s19.BridgeCompareLPPaResultNR(&first, &comparison)
	s19.BridgeCompareLPPaResultNR(&second, &comparison)
	comparison.End(current, root, false)
	if err := comparison.ChargeComparison(budget); err != nil {
		t.Fatalf("list value scope escaped into its sibling: %v", err)
	}
	if !comparison.Unchanged(root) {
		t.Fatal("equal list values changed")
	}
}
