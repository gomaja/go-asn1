package lppa

import (
	q9 "bytes"
	q16 "errors"
	q15 "fmt"
	bridge0 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"

	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q8 "testing"
)

// X.691 (02/2021) §§11.2.1,11.9.3.8: changing a sibling IE keeps
// an unknown fragmented IE's received contents exact under raised limits.
func TestReplayEditedMessageKeepsLargeFragmentedUnknownIE(t *q8.T) {
	payload := q9.Repeat([]byte{0xa5}, 9<<20)
	unknown := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65535, CriticalityIgnore, payload))
	known := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{}))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{known, unknown}}
	// These are operational ceilings, not new source constraints.
	limits := q14.Limits{MaxWork: 1 << 30, MaxAllocatedBytes: 512 << 20, MaxInputBytes: 32 << 20, MaxOutputBytes: 32 << 20, MaxOpenTypeBytes: 32 << 20}
	encoded := sliceByteReplayMust(body.MarshalAPER(q14.WithEncodeLimits(limits)))
	var value ErrorIndication
	report, err := value.UnmarshalAPER(encoded, q14.WithLimits(limits))
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("decode: %v observations=%d", err, len(report.Observations))
	}
	value.ProtocolIEs[0] = errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{ProcedureCode: new(ProcedureCode(2))}))
	changed, err := value.MarshalAPER(q14.WithEncodeLimits(limits))
	if err != nil {
		t.Fatal(err)
	}
	if q9.Equal(changed, encoded) {
		t.Fatal("known edit did not change encoding")
	}
	var check ErrorIndication
	if _, err := check.UnmarshalAPER(changed, q14.WithLimits(limits)); err != nil {
		t.Fatal(err)
	}
	id, ok := check.ProtocolIEs[0].Value.AsCriticalityDiagnostics()
	if !ok || id == nil || id.ProcedureCode == nil || *id.ProcedureCode != 2 {
		t.Fatal("known edit lost")
	}
	raw, ok := check.ProtocolIEs[1].Value.Opaque()
	if !ok || !q9.Equal(raw.Bytes(), payload) {
		t.Fatalf("unknown contents lost: opaque=%t bytes=%d", ok, len(raw.Bytes()))
	}
	if replay, err := check.MarshalAPER(q14.WithEncodeLimits(limits)); err != nil || !q9.Equal(replay, changed) {
		t.Fatalf("edited result replay: %v", err)
	}
}
func TestReplayFragmentedMessageAllocationBoundaries(t *q8.T) {
	var previousAllocation, previousWork uint64
	for _, size := range []int{65540, 131080, 262160} {
		t.Run(q15.Sprint(size), func(t *q8.T) {
			payload := q9.Repeat([]byte{0xa5}, size)
			unknown := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65535, CriticalityIgnore, payload))
			known := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{}))
			body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{known, unknown}}
			wire := sliceByteReplayMust(body.MarshalAPER())
			data, state := q14.OwnDecodeInputOptions(wire)
			var decoded ErrorIndication
			if err := bridge0.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&decoded, data, state); err != nil {
				t.Fatal(err)
			}
			capture := q14.SemanticCaptureFor(state)
			bridge0.BridgeCaptureLPPaErrorIndication(&decoded, &capture)
			if _, err := q14.FinishDecode(state, nil); err != nil {
				t.Fatal(err)
			}
			usage := state.Usage()
			for _, limit := range []uint64{usage.AllocatedBytes - 1, usage.AllocatedBytes, usage.AllocatedBytes + 1} {
				for _, reused := range []bool{false, true} {
					for _, receiver := range []bool{false, true} {
						var value ErrorIndication
						if reused {
							if _, err := value.UnmarshalAPER(wire); err != nil {
								t.Fatal(err)
							}
						}
						options := []q14.DecodeOption{q14.WithLimits(q14.Limits{MaxAllocatedBytes: limit})}
						if receiver {
							options = append(options, q14.WithReceiverMode())
						}
						report, err := value.UnmarshalAPER(wire, options...)
						if (limit < usage.AllocatedBytes) != q16.Is(err, q14.ErrLimit) {
							t.Fatalf("limit=%d need=%d reused=%t receiver=%t err=%v", limit, usage.AllocatedBytes, reused, receiver, err)
						}
						if err != nil {
							var located *q14.DecodeError
							if !q16.As(err, &located) || !located.Location.HasWireLocation || located.Location.Path == "" {
								t.Fatalf("unlocated error %v", err)
							}
							if len(value.ProtocolIEs) != 0 {
								t.Fatal("failed decode retained the old value")
							}
						} else {
							raw, ok := value.ProtocolIEs[1].Value.Opaque()
							if !ok || len(report.Observations) != 1 || !q9.Equal(raw.Bytes(), payload) {
								t.Fatal("fragmented contents or observation lost")
							}
						}
					}
				}
			}
			if previousAllocation != 0 && (usage.AllocatedBytes > previousAllocation*3 || usage.Work > previousWork*3) {
				t.Fatal("nonlinear fragmented accounting")
			}
			previousAllocation, previousWork = usage.AllocatedBytes, usage.Work
			t.Logf("contents=%d allocated=%d work=%d", size, usage.AllocatedBytes, usage.Work)
		})
	}
}
