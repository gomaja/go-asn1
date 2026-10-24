// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	errors "errors"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
	unsafe "unsafe"
)

// TS 36.413 V19.2.0 Annex B.2 supplies the root; X.691 (02/2021)
// §§19.7–19.9 supplies the extension bitmap and complete open contents.
func TestExtensionBitmapReservesAllReplayArrays(t *testing.T) {
	var previous uint64
	for _, count := range []int{256, 512, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			w := aper.NewBitBuffer()
			if err := aper.EncodeBoolean(w, true); err != nil {
				t.Fatal(err)
			}
			if err := aper.EncodeOctetStringAligned(w, nil, 0, 0, false); err != nil {
				t.Fatal(err)
			}
			if err := aper.EncodeNormallySmallLengthAligned(w, int64(count)); err != nil {
				t.Fatal(err)
			}
			for i := range count {
				if err := aper.EncodeBoolean(w, i == count-1); err != nil {
					t.Fatal(err)
				}
			}
			if err := aper.EncodeOpenTypeAligned(w, []byte{0xa5}); err != nil {
				t.Fatal(err)
			}
			wire := w.CompleteBytes()
			data, state := aper.StartDecode(wire)
			bb := aper.NewCompleteDecodeBuffer(data, state)
			if err := bb.SetDecodeOptionsAligned(state); err != nil {
				t.Fatal(err)
			}
			if _, err := aper.DecodeBoolean(bb); err != nil {
				t.Fatal(err)
			}
			if _, err := aper.DecodeOctetStringAligned(bb, 0, 0, false); err != nil {
				t.Fatal(err)
			}
			additions := aper.BeginExtensionAdditions(bb)
			if _, _, err := additions.DecodeBitmapAligned(bb); err != nil {
				t.Fatal(err)
			}
			before := state.Usage().AllocatedBytes
			var decoded s17.EUTRANcellLoadReportingResponse
			data, state = aper.StartDecode(wire)
			if err := s17.BridgeEUTRANcellLoadReportingResponseMethodUnmarshalAPERWithOptions(&decoded, data, state); err != nil {
				t.Fatal(err)
			}
			capture := aper.SemanticCaptureFor(state)
			s17.BridgeCaptureS1APEUTRANcellLoadReportingResponse(&decoded, &capture)
			if _, err := aper.FinishDecode(state, nil); err != nil {
				t.Fatal(err)
			}
			allocated := state.Usage().AllocatedBytes
			arrays := uint64(count) * (uint64(unsafe.Sizeof([]byte{})) + uint64(unsafe.Sizeof(aper.OpaqueOrigin{})) + uint64(unsafe.Sizeof(aper.WireSpan{})))
			if allocated < before+arrays {
				t.Fatalf("reserved=%d before=%d replay arrays=%d", allocated, before, arrays)
			}
			// A ceiling one byte below the minimum still refuses at limit; +1 is
			// the first success. No failed call may publish the previous receiver.
			ceiling := allocated - 1
			for _, limit := range []uint64{ceiling - 1, ceiling, ceiling + 1, ceiling + 2} {
				for _, reused := range []bool{false, true} {
					var value s17.EUTRANcellLoadReportingResponse
					if reused {
						if _, err := value.UnmarshalAPER(wire); err != nil {
							t.Fatal(err)
						}
					}
					report, err := value.UnmarshalAPER(wire, aper.WithLimits(aper.Limits{MaxAllocatedBytes: limit}))
					if (limit < allocated) != errors.Is(err, aper.ErrLimit) {
						t.Fatalf("limit=%d required=%d reused=%t err=%v", limit, allocated, reused, err)
					}
					if err != nil {
						var located *aper.DecodeError
						if !errors.As(err, &located) || !located.Location.HasWireLocation || located.Location.Path == "" {
							t.Fatalf("unlocated error=%v", err)
						}
						if len(value.Extensions()) != 0 {
							t.Fatal("failed decode published old extensions")
						}
					} else if len(report.Observations) != 1 {
						t.Fatalf("observations=%d", len(report.Observations))
					}
				}
			}
			t.Logf("bitmap=%d reserved=%d arrays=%d", count, allocated, arrays)
			if previous != 0 && allocated > previous*3 {
				t.Fatal("nonlinear accounting")
			}
			previous = allocated
		})
	}
}

// X.691 (02/2021) §§11.2.1,11.9.3.8: changing a sibling IE keeps
// an unknown fragmented IE's received contents exact under raised limits.
func TestEditedMessageKeepsLargeFragmentedUnknownIE(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 9<<20)
	unknown := errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().NewOpaque(65535, s00.CriticalityIgnore, payload))
	known := errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().MMEUES1APID().New(1))
	body := s28.ErrorIndication{ProtocolIEs: s28.ErrorIndicationIEContainer{known, unknown}}
	// These are operational ceilings, not new source constraints.
	limits := aper.Limits{MaxWork: 1 << 30, MaxAllocatedBytes: 512 << 20, MaxInputBytes: 32 << 20, MaxOutputBytes: 32 << 20, MaxOpenTypeBytes: 32 << 20}
	encoded := sliceByteFreshMust(body.MarshalAPER(aper.WithEncodeLimits(limits)))
	var value s28.ErrorIndication
	report, err := value.UnmarshalAPER(encoded, aper.WithLimits(limits))
	if err != nil || len(report.Observations) != 1 {
		t.Fatalf("decode: %v observations=%d", err, len(report.Observations))
	}
	value.ProtocolIEs[0] = errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().MMEUES1APID().New(2))
	changed, err := value.MarshalAPER(aper.WithEncodeLimits(limits))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(changed, encoded) {
		t.Fatal("known edit did not change encoding")
	}
	var check s28.ErrorIndication
	if _, err := check.UnmarshalAPER(changed, aper.WithLimits(limits)); err != nil {
		t.Fatal(err)
	}
	id, ok := check.ProtocolIEs[0].Value.AsMMEUES1APID()
	if !ok || id == nil || *id != 2 {
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
func TestFragmentedMessageAllocationBoundaries(t *testing.T) {
	var previousAllocation, previousWork uint64
	for _, size := range []int{65540, 131080, 262160} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, size)
			unknown := errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().NewOpaque(65535, s00.CriticalityIgnore, payload))
			known := errorIndicationIEFieldFreshMust(s28.ErrorIndicationIEs().MMEUES1APID().New(1))
			body := s28.ErrorIndication{ProtocolIEs: s28.ErrorIndicationIEContainer{known, unknown}}
			wire := sliceByteFreshMust(body.MarshalAPER())
			data, state := aper.StartDecode(wire)
			var decoded s28.ErrorIndication
			if err := s28.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&decoded, data, state); err != nil {
				t.Fatal(err)
			}
			capture := aper.SemanticCaptureFor(state)
			s28.BridgeCaptureS1APErrorIndication(&decoded, &capture)
			if _, err := aper.FinishDecode(state, nil); err != nil {
				t.Fatal(err)
			}
			usage := state.Usage()
			for _, limit := range []uint64{usage.AllocatedBytes - 1, usage.AllocatedBytes, usage.AllocatedBytes + 1} {
				for _, reused := range []bool{false, true} {
					for _, receiver := range []bool{false, true} {
						var value s28.ErrorIndication
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
