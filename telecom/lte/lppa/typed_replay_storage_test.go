package lppa

import (
	q9 "encoding/hex"
	q16 "errors"
	bridge1 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"

	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q10 "runtime"
	q8 "testing"
	q12 "unsafe"
)

func TestReplaySmallMessageStorage(t *q8.T) {
	for _, row := range []struct {
		hex   string
		bytes uint64
	}{
		{"000040000003000000", 1920},
		{"0002000000080000010002000100", 2560},
		{"00020000010d00000200020001300003000140", 5120},
	} {
		wire, err := q9.DecodeString(row.hex)
		if err != nil {
			t.Fatal(err)
		}
		q10.GC()
		var before, after q10.MemStats
		q10.ReadMemStats(&before)
		for range 100 {
			var v LPPAPDU
			if _, err := v.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			replayDecodeSink = v
		}
		q10.ReadMemStats(&after)
		got := (after.TotalAlloc - before.TotalAlloc) / 100
		t.Logf("input=%d bytes/op=%d ceiling=%d", len(wire), got, row.bytes)
		if got > row.bytes {
			t.Errorf("input=%d allocated %d bytes/op, want at most %d", len(wire), got, row.bytes)
		}
	}
}
func TestReplayKnownUnionStorageBudget(t *q8.T) {
	if got := q12.Sizeof(InitiatingValue{}); got > 256 {
		t.Errorf("known procedure union uses %d bytes, want at most 256", got)
	}
	if got := q12.Sizeof(ECIDMeasurementInitiationRequestIEValue{}); got > 256 {
		t.Errorf("known IE union uses %d bytes, want at most 256", got)
	}
}
func TestReplayProcedureScopeLimitKeepsChildOrigin(t *q8.T) {
	wire, state := q15.OwnDecodeInputOptions([]byte{3, 0, 0, 0})
	bb := q15.NewCompleteDecodeBuffer(wire, state)
	raw, err := q15.DecodeOpaqueOpenTypeAligned(bb, q15.UnknownSelector, q15.SourceRule{})
	if err != nil {
		t.Fatal(err)
	}
	for range q15.DefaultLimits().MaxDepth {
		if err := bb.EnterOpenType(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = bridge0.BridgeDecodeInitiatingValue(0, raw)
	var located *q15.DecodeError
	if !q16.As(err, &located) || located.Kind != q15.Limit || len(located.Location.Spans) != 1 || located.Location.Spans[0] != (q15.BitSpan{Start: 8, End: 8}) {
		t.Fatalf("selected child scope lost its original start: %v", err)
	}
}
func TestReplayNamedListScopesAreIndependent(t *q8.T) {
	first, second := make(ResultNR, 1), make(ResultNR, 1)
	capture := q15.NewSemanticCapture(1024)
	frame := capture.Begin()
	bridge1.BridgeCaptureLPPaResultNR(&first, &capture)
	bridge1.BridgeCaptureLPPaResultNR(&second, &capture)
	var root q15.Snapshot
	capture.End(frame, &root, false)
	budget, err := q15.EncodeBudget(q15.WithEncodeLimits(q15.Limits{MaxDepth: 2}))
	if err != nil {
		t.Fatal(err)
	}
	comparison := q15.NewSemanticComparison(root, q15.ComparisonBudget(budget))
	current := comparison.Begin()
	bridge1.BridgeCompareLPPaResultNR(&first, &comparison)
	bridge1.BridgeCompareLPPaResultNR(&second, &comparison)
	comparison.End(current, root, false)
	if err := comparison.ChargeComparison(budget); err != nil {
		t.Fatalf("list value scope escaped into its sibling: %v", err)
	}
	if !comparison.Unchanged(root) {
		t.Fatal("equal list values changed")
	}
}
