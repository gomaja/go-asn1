// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/owned_mechanisms_test.go; SHA-256 2fe379c908e52bd477df9f5d06334a4c66609fd5275aa2fb90ffb1f0832bbfc3.
package ber

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestOwnedReplayCaptureOptOut(t *testing.T) {
	for _, mode := range []DecodeOption{ForceGeneratedBERLightForTesting(), ForceGeneratedBERProofForTesting()} {
		wire := []byte{4, 0x81, 1, 'A'}
		options := TrackBERForm([]DecodeOption{mode, WithoutReplayCapture()})
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		data, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		if node := CaptureGeneratedBERReplay(data, options); node != nil {
			t.Fatal("capture opt-out retained replay authority")
		}
		if _, n, err := DecodeOctetString(data, options...); err != nil || n != len(data) {
			t.Fatalf("capture opt-out changed decoding: %d %v", n, err)
		}
	}
}

func TestOwnedModeLimits(t *testing.T) {
	for _, tc := range []struct {
		mode  DecodeOption
		light bool
	}{{ForceGeneratedBERLightForTesting(), true}, {ForceGeneratedBERProofForTesting(), false}} {
		wire := []byte{0x30, 3, 4, 1, 'A'}
		options := TrackBERForm([]DecodeOption{tc.mode})
		data, err := OwnGeneratedBERInput(wire, options)
		if err != nil {
			t.Fatal(err)
		}
		_, options, err = PrepareGeneratedBERInput(data, options)
		if err != nil {
			t.Fatal(err)
		}
		context, ok := options[0].(*generatedDecodeOption)
		if !ok || context.source.light != tc.light {
			t.Fatalf("forced mode lost: light=%t options=%T", tc.light, options[0])
		}
		limited := TrackBERForm([]DecodeOption{tc.mode, WithDecodeLimits(DecodeLimits{MaxWork: len(wire) - 1})})
		data, err = OwnGeneratedBERInput(wire, limited)
		if err == nil {
			_, _, err = PrepareGeneratedBERInput(data, limited)
		}
		if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("forced mode weakened work limit: %v", err)
		}
	}
}

func TestOwnedViolationSnapshotsDetached(t *testing.T) {
	var log ViolationLog
	options, finish := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
	wire := []byte{0x30, 3, 4, 1, 'A'}
	options = LocateDecodedElement(wire, "Module.Type", options)
	MarkPreflightTarget(options, "field", wire[2:])
	if err := CheckDecodedLength(options, "field", "SIZE (2)", 1); err != nil {
		t.Fatal(err)
	}
	finish(true)
	saved := log.Snapshot()
	copy := log.Snapshot()
	*copy[0].Offset = 100
	copy[0].ChildIndexes[0] = 100
	*copy[0].ObservedLength = 100
	if len(saved) != 1 || *saved[0].Offset != 2 || !reflect.DeepEqual(log.Snapshot()[0].ChildIndexes, []int{0}) || *log.Snapshot()[0].ObservedLength != 1 || *log.Snapshot()[0].Offset != 2 {
		t.Fatal("snapshot aliases retained positions or lengths")
	}
	log.Reset()
	if len(log.Snapshot()) != 0 {
		t.Fatal("reset retained records")
	}
	if !bytes.Equal(wire, []byte{0x30, 3, 4, 1, 'A'}) {
		t.Fatal("reporting changed input")
	}
}

func TestOwnedScannerDepthBoundaries(t *testing.T) {
	for _, indefinite := range []bool{false, true} {
		for _, depth := range []int{1, 2, 8, 64} {
			wire := []byte{5, 0}
			for range depth {
				if indefinite {
					wire = append(append([]byte{0x30, 0x80}, wire...), 0, 0)
				} else {
					var err error
					wire, err = EncodeSequence(wire)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := ValidateBERElement(wire, WithDecodeLimits(DecodeLimits{MaxDepth: depth})); err != nil {
				t.Fatalf("depth %d indefinite %v: %v", depth, indefinite, err)
			}
			if depth > 1 {
				if err := ValidateBERElement(wire, WithDecodeLimits(DecodeLimits{MaxDepth: depth - 1})); !errors.Is(err, ErrResourceLimit) {
					t.Fatalf("depth %d indefinite %v limit ignored: %v", depth, indefinite, err)
				}
			}
		}
	}
}
