// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_external_forms_test.go; SHA-256 4266bf635538cb61d8b3ba2fedca9d69ce4ee58bbbce069dc1832242a2af8fa3.
package ber

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// EXTERNAL owns its framing and choice wrapper while its encoded data value
// stays foreign (X.690 (02/2021) §§8.18.9-8.18.11).

func externalRepairWire(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertExternalRepair(t *testing.T, name, original, want string, profiled bool, edit func(*runtime.External)) {
	t.Helper()
	value, n, err := DecodeExternal(externalRepairWire(t, original))
	if err != nil || n != len(original)/2 {
		t.Fatalf("%s decode: %d %v", name, n, err)
	}
	edit(&value)
	opts := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true, mapProfileChecked: profiled}, rebuildChildren: true}}
	got, err := EncodeExternal(value, opts...)
	t.Logf("EXTERNAL %s got=%x err=%v", name, got, err)
	if err != nil || !bytes.Equal(got, externalRepairWire(t, want)) {
		t.Errorf("%s: got %x want %s: %v", name, got, want, err)
	}
}

func TestMAPExternalRepairForms(t *testing.T) {
	dr := func(v *runtime.External) { v.DirectReference = runtime.MustObjectIdentifier("1.2.4") }
	// TCAP TestExternalPrimitiveRepair, second half: edited bits rebuilt.
	assertExternalRepair(t, "edited-bits", "28810806022a03820207ff", "280806022a0482020700", true, func(v *runtime.External) {
		dr(v)
		v.Arbitrary.Bytes[0] = 0
	})
	// TCAP TestEditedArbitraryStaysOpaque.
	assertExternalRepair(t, "arbitrary-opaque", "28810a06022a038204078101ff", "280906022a038203070180", true, func(v *runtime.External) {
		v.Arbitrary.Bytes = []byte{1, 128}
		v.Arbitrary.BitLength = 9
	})
	// TCAP TestExternalDescriptorFormRepair.
	assertExternalRepair(t, "descriptor-form", "28810d06022a03270304014181024243", "280d06022a04270304014181024243", true, dr)
	// octet-aligned in constructed form is a profile violation: rebuilt primitive.
	assertExternalRepair(t, "octet-aligned-constructed", "280b06022a03a1050403414243", "280906022a048103414243", true, dr)
	// single-ASN1-type: the encoded data value is foreign; its long form stays.
	assertExternalRepair(t, "single-type-foreign-long", "28810a06022a03a00404810141", "280a06022a04a00404810141", true, dr)
	// Generic root (no TS 29.002 profile): no repair; fresh encoding.
	assertExternalRepair(t, "generic-root", "28810806022a03820207ff", "280806022a0482020780", false, dr)
}

func TestMAPExternalUnchangedSnapshotInEditedParent(t *testing.T) {
	// The parent changed, but this EXTERNAL did not. Its own snapshot must
	// still satisfy TS 29.002 V19.1.0 §17.1.1 before reuse; X.690 (02/2021)
	// §8.18.10 makes [1] an IMPLICIT OCTET STRING, not an opaque constructor.
	for _, row := range []struct{ name, wire, want string }{
		{"short-length", "28810806022a03820207ff", "280806022a03820207ff"},
		{"constructed-octet-aligned", "280b06022a03a1050403414243", "280906022a038103414243"},
	} {
		t.Run(row.name, func(t *testing.T) {
			value, _, err := DecodeExternal(externalRepairWire(t, row.wire))
			if err != nil {
				t.Fatal(err)
			}
			options := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true, mapProfileChecked: true}, rebuildChildren: true}}
			got, err := EncodeExternal(value, options...)
			if err != nil || !bytes.Equal(got, externalRepairWire(t, row.want)) {
				t.Fatalf("snapshot replay=%x want=%s: %v", got, row.want, err)
			}
		})
	}
}

func TestMAPExternalCollectionKeepsOccurrenceSnapshot(t *testing.T) {
	// X.690 (02/2021) §8.18: each EXTERNAL owns its detached snapshot.
	// After a reorder, equal significant bits do not license using the
	// previous occupant's padding. Only the parent length violates §17.1.1.
	received := externalRepairWire(t, "308114280806022a03820207ff280806022a0482020780")
	baseline := externalRepairWire(t, "3014280806022a0382020780280806022a0482020780")
	current := externalRepairWire(t, "3014280806022a0482020780280806022a03820207ff")
	state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{0}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	if got := replayUnchangedParts(current, node); !bytes.Equal(got, current) {
		t.Fatalf("collection inherited sibling form: %x want %x", got, current)
	}
}
