package lppa

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"

	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"testing"
)

// X.691 (02/2021) §§11.2.1,11.9.3.8: changing a sibling IE keeps
// an unknown fragmented IE's received contents exact under raised limits.
func TestReplayEditedMessageKeepsLargeFragmentedUnknownIE(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 9<<20)
	unknown := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65535, CriticalityIgnore, payload))
	known := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{}))
	body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{known, unknown}}
	// These are operational ceilings, not new source constraints.
	limits := aper.Limits{MaxWork: 1 << 30, MaxAllocatedBytes: 512 << 20, MaxInputBytes: 32 << 20, MaxOutputBytes: 32 << 20, MaxOpenTypeBytes: 32 << 20}
	encoded := sliceByteReplayMust(body.MarshalAPER(aper.WithEncodeLimits(limits)))
	var value ErrorIndication
	report, err := value.UnmarshalAPER(encoded, aper.WithLimits(limits))
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("decode: %v observations=%d", err, len(report.Observations))
	}
	value.ProtocolIEs[0] = errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{ProcedureCode: new(ProcedureCode(2))}))
	changed, err := value.MarshalAPER(aper.WithEncodeLimits(limits))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(changed, encoded) {
		t.Fatal("known edit did not change encoding")
	}
	var check ErrorIndication
	if _, err := check.UnmarshalAPER(changed, aper.WithLimits(limits)); err != nil {
		t.Fatal(err)
	}
	id, ok := check.ProtocolIEs[0].Value.AsCriticalityDiagnostics()
	if !ok || id == nil || id.ProcedureCode == nil || *id.ProcedureCode != 2 {
		t.Fatal("known edit lost")
	}
	raw, ok := check.ProtocolIEs[1].Value.Opaque()
	if !ok || !bytes.Equal(raw.Bytes(), payload) {
		t.Fatalf("unknown contents lost: opaque=%t bytes=%d", ok, len(raw.Bytes()))
	}
	if replay, err := check.MarshalAPER(aper.WithEncodeLimits(limits)); err != nil || !bytes.Equal(replay, changed) {
		t.Fatalf("edited result replay: %v", err)
	}
}
func TestReplayFragmentedMessageAllocationBoundaries(t *testing.T) {
	var previousAllocation, previousWork uint64
	for _, size := range []int{65540, 131080, 262160} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, size)
			unknown := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().NewOpaque(65535, CriticalityIgnore, payload))
			known := errorIndicationIEFieldReplayMust(ErrorIndicationIEs().CriticalityDiagnostics().New(CriticalityDiagnostics{}))
			body := ErrorIndication{ProtocolIEs: ErrorIndicationIEContainer{known, unknown}}
			wire := sliceByteReplayMust(body.MarshalAPER())
			data, state := aper.OwnDecodeInputOptions(wire)
			var decoded ErrorIndication
			if err := s11.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&decoded, data, state); err != nil {
				t.Fatal(err)
			}
			capture := aper.SemanticCaptureFor(state)
			s11.BridgeCaptureLPPaErrorIndication(&decoded, &capture)
			if _, err := aper.FinishDecode(state, nil); err != nil {
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
						options := []aper.DecodeOption{aper.WithLimits(aper.Limits{MaxAllocatedBytes: limit})}
						if receiver {
							options = append(options, aper.WithReceiverMode())
						}
						report, err := value.UnmarshalAPER(wire, options...)
						if (limit < usage.AllocatedBytes) != errors.Is(err, aper.ErrLimit) {
							t.Fatalf("limit=%d need=%d reused=%t receiver=%t err=%v", limit, usage.AllocatedBytes, reused, receiver, err)
						}
						if err != nil {
							var located *aper.DecodeError
							if !errors.As(err, &located) || !located.Location.HasWireLocation || located.Location.Path == "" {
								t.Fatalf("unlocated error %v", err)
							}
							if len(value.ProtocolIEs) != 0 {
								t.Fatal("failed decode retained the old value")
							}
						} else {
							raw, ok := value.ProtocolIEs[1].Value.Opaque()
							if !ok || len(report.Observations) != 1 || !bytes.Equal(raw.Bytes(), payload) {
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
