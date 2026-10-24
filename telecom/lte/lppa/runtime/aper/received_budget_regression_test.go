// Code generated from LPPa runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/received_budget_regression_test.go; SHA-256 01fe9ece4e84103990d523a59855bd407bd9e4ae32c935e02b933e67e3c760ce.
package aper

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"unsafe"
)

func TestStandaloneWriterKeepsLargeCopyBehaviour(t *testing.T) {
	for _, size := range []int{9 << 20, 17 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{0xa5}, size)
			bb := NewBitBuffer()
			if err := bb.WriteBytes(payload); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bb.Bytes(), payload) {
				t.Fatal("standalone writer changed contents")
			}
		})
	}
}

func TestSegmentedSpanCopiesWithoutIndependentCeiling(t *testing.T) {
	for _, size := range []int{8 << 20, 9 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			original := bytes.Repeat([]byte{0xa5}, size+1)
			original[size/2] = 0x7e
			span := WireSpan{original: original, segments: []BitSpan{{Start: 0, End: uint64(size/2) * 8}, {Start: uint64(size/2+1) * 8, End: uint64(size+1) * 8}}}
			want := bytes.Repeat([]byte{0xa5}, size)
			for name, copy := range map[string]func() []byte{"span": span.Bytes, "opaque": (OpaqueOpenType{image: span}).Bytes, "choice": (ChoiceExtension{image: span}).Contents, "received": (ReceivedForm{image: span}).OriginalBytes} {
				if got := copy(); !bytes.Equal(got, want) {
					t.Errorf("%s: copied %d bytes, want %d", name, len(got), size)
				}
			}
		})
	}
}

func TestReceivedCopyErrorsReachEncoders(t *testing.T) {
	// A corrupt internal span must never become successful empty open contents.
	invalid := WireSpan{original: []byte{1}, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	for name, run := range map[string]func() error{
		"replay": func() error { budget, _ := EncodeBudget(); _, err := invalid.ReplayBytes(budget); return err },
		"opaque": func() error {
			budget, _ := EncodeBudget()
			_, err := (OpaqueOpenType{image: invalid}).EncodeBytes(budget)
			return err
		},
		"choice": func() error { return (ChoiceExtension{image: invalid}).EncodeTo(NewBitBuffer()) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrInvalidValue) {
				t.Fatalf("copy failure discarded: %v", err)
			}
		})
	}
}

// Copy reservations use the enclosing complete decoder, including framed
// origins and fragmented contents (X.691 (02/2021) §§11.2.1, 11.9.3.8).
func TestOwnedLocationCopiesShareParentBudget(t *testing.T) {
	for _, size := range []int{1, 65540} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			w := NewBitBuffer()
			if err := EncodeOpenTypeAligned(w, bytes.Repeat([]byte{0xa5}, size)); err != nil {
				t.Fatal(err)
			}
			wire := w.Bytes()
			setup := func(limit uint64) (DecodeState, OpaqueOpenType) {
				owned, state := OwnDecodeInputOptions(wire, WithLimits(Limits{MaxAllocatedBytes: limit}))
				bb := NewCompleteDecodeBuffer(owned, state)
				if err := bb.SetDecodeOptionsAligned(state); err != nil {
					t.Fatal(err)
				}
				raw, err := DecodeOpaqueOpenTypeAligned(bb, UnknownSelector, SourceRule{})
				if err != nil {
					t.Fatal(err)
				}
				return state, raw
			}
			state, raw := setup(0)
			for name, get := range map[string]func(OpaqueOpenType) Location{
				"framing":  func(v OpaqueOpenType) Location { return v.Origin().Location },
				"contents": func(v OpaqueOpenType) Location { return v.ContentLocation() },
			} {
				t.Run(name, func(t *testing.T) {
					before := state.Usage().AllocatedBytes
					// Access the immutable span only to independently compute the copy size.
					span := raw.image
					if name == "framing" {
						span = raw.framing
					}
					count := max(1, len(span.segments))
					required := before + uint64(count)*16
					for _, limit := range []uint64{required - 1, required, required + 1} {
						current, value := setup(limit)
						location := get(value)
						_, err := FinishDecode(current, nil)
						if (limit < required) != errors.Is(err, ErrLimit) {
							t.Fatalf("limit=%d required=%d err=%v", limit, required, err)
						}
						if err != nil {
							var located *DecodeError
							if !errors.As(err, &located) || !located.Location.HasWireLocation {
								t.Fatalf("unlocated limit: %v", err)
							}
							continue
						}
						if got := current.Usage().AllocatedBytes; got != required {
							t.Fatalf("charged=%d want=%d", got, required)
						}
						if len(location.Spans) != count || !location.HasWireLocation {
							t.Fatalf("location=%+v", location)
						}
						location.Spans[0].Start = 999
						if get(value.Detached()).Spans[0].Start == 999 {
							t.Fatal("location aliases owner")
						}
					}
				})
			}
		})
	}
}

func TestExtensionContentCopyFailuresReachEncoder(t *testing.T) {
	invalid := WireSpan{original: []byte{1}, segments: []BitSpan{{Start: 0, End: 8}, {Start: 16, End: 24}}}
	budget, err := EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CopyExtensionContents(nil, []WireSpan{invalid}, budget); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("copy error discarded: %v", err)
	}
	octets := []byte{0xa5, 0x5a}
	image := OriginalWire(octets)
	// The copy charges one [][]byte element and its octets. The element's size
	// is the target architecture's slice header, as the budget charges it.
	required := operationMetadataBytes + uint64(unsafe.Sizeof([]byte(nil))) + uint64(len(octets))
	for _, limit := range []uint64{operationMetadataBytes, required - 1} {
		budget, err := EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: limit}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := CopyExtensionContents(nil, []WireSpan{image}, budget); !errors.Is(err, ErrLimit) {
			t.Fatalf("limit=%d required=%d: copy escaped allocation budget: %v", limit, required, err)
		}
	}
	exact, err := EncodeBudget(WithEncodeLimits(Limits{MaxAllocatedBytes: required}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CopyExtensionContents(nil, []WireSpan{image}, exact); err != nil {
		t.Fatalf("limit=%d: copy within its budget failed: %v", required, err)
	}
	budget, err = EncodeBudget()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := CopyExtensionContents([][]byte{nil, {0x80}}, []WireSpan{image}, budget)
	if err != nil || !bytes.Equal(contents[0], image.Bytes()) || !bytes.Equal(contents[1], []byte{0x80}) {
		t.Fatalf("contents=%x err=%v", contents, err)
	}
}
