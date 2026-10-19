// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_parts_test.go; SHA-256 2d8aadffdbaaa6c612fe0c95e06d089a427fd4897878b10a1d246daa9526aece.
package ber

import (
	"bytes"
	"encoding/hex"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"testing"
)

func repairHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The BOOL and BIT STRING forms are legal BER: X.690 (02/2021)
// §§8.2.2, 8.6.2.2. Zero padding belongs to CER/DER §11.2.1.
func TestRepairKeepsPrimitiveForms(t *testing.T) {
	for _, row := range []struct{ name, received, baseline, current, want string }{
		{"boolean", "3009040101010101058100", "30080401010101ff0500", "30080401020101ff0500", "30080401020101010500"},
		{"bit-padding", "300a040101800207ff058100", "3009040101800207800500", "3009040102800207800500", "3009040102800207ff0500"},
		{"edited-boolean", "3009040101010101058100", "30080401010101ff0500", "30080401020101000500", "30080401020101000500"},
		{"edited-padding-value", "300a040101800207ff058100", "3009040101800207800500", "3009040102800207000500", "3009040102800207000500"},
	} {
		t.Run(row.name, func(t *testing.T) {
			received := repairHex(t, row.received)
			baseline := repairHex(t, row.baseline)
			current := repairHex(t, row.current)
			state := &ReplayState{decodeTolerant: true, baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{len(received) - 3}}}
			node := &ReplayNode{state: state, original: received}
			state.root = node
			for _, kind := range []string{"typed", "ordinary", "fast"} {
				mode := replayModeOption{state: state, top: node, rebuildChildren: true}
				if kind == "typed" {
					mode.typed = new(BERReplayComparisons)
				}
				if kind == "fast" {
					mode.fast = &replayFastState{state: state, root: node, stack: []replayFastFrame{{node: node}}}
				}
				got := PreserveEncodedBERNode(current, node, []EncodeOption{mode})
				if !bytes.Equal(got, repairHex(t, row.want)) {
					t.Fatalf("%s: %x want %s", kind, got, row.want)
				}
				if err := ValidateBERElement(got, tcapEncodedProfileOption{kind: ""}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// A Q.773 (06/1997) §4.1.1 finding on an owned sibling cannot turn an
// X.690 (02/2021) §8.15 open-type header into a TCAP repair target.
func TestRepairPreservesForeignHeaderWithoutProfileFinding(t *testing.T) {
	received := repairHex(t, "300a04810101308103040100")
	baseline := repairHex(t, "30080401013003040100")
	current := repairHex(t, "30080401023003040100")
	state := &ReplayState{decodeTolerant: true, baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{2}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	got := replayUnchangedParts(current, node)
	want := repairHex(t, "3009040102308103040100")
	if !bytes.Equal(got, want) {
		t.Fatalf("foreign header changed: %x want %x", got, want)
	}
}

func TestExternalRepairIndexesChoiceButNotForeignValue(t *testing.T) {
	// Q.773 (06/1997) §4.1.1 covers EXTERNAL's choice header; X.690
	// (02/2021) §8.18.9 leaves the complete single-ASN1-type TLV foreign.
	part := replayPartRoot(repairHex(t, "280d06022a03a08106308103040100"))
	if part == nil {
		t.Fatal("synthetic EXTERNAL did not parse")
	}
	index := new(replayProfileIndex)
	collectReplayPartViolations(part, index, true, false)
	if len(index.offsets) != 1 || index.offsets[0] != 6 {
		t.Fatalf("profile offsets %v, want choice header only", index.offsets)
	}
}

func TestRepairPrimitiveVariants(t *testing.T) {
	for value := 1; value < 256; value++ {
		received := []byte{0x30, 9, 4, 1, 1, 1, 1, byte(value), 5, 0x81, 0}
		baseline := []byte{0x30, 8, 4, 1, 1, 1, 1, 255, 5, 0}
		current := bytes.Clone(baseline)
		current[4] = 2
		state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{8}}}
		node := &ReplayNode{state: state, original: received}
		state.root = node
		got := replayUnchangedParts(current, node)
		if got[7] != byte(value) {
			t.Fatalf("TRUE %x became %x", value, got)
		}
	}
	for padding := 0; padding < 128; padding++ {
		received := []byte{0x30, 10, 4, 1, 1, 0x80, 2, 7, 0x80 | byte(padding), 5, 0x81, 0}
		baseline := []byte{0x30, 9, 4, 1, 1, 0x80, 2, 7, 0x80, 5, 0}
		current := bytes.Clone(baseline)
		current[4] = 2
		state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{9}}}
		node := &ReplayNode{state: state, original: received}
		state.root = node
		got := replayUnchangedParts(current, node)
		if got[8] != 0x80|byte(padding) {
			t.Fatalf("padding %x became %x", padding, got)
		}
	}
}

func TestRepairPartsGrowth(t *testing.T) {
	for _, count := range []int{64, 128, 256, 512} {
		oldContent := append([]byte{4, 1, 1}, bytes.Repeat([]byte{1, 1, 1}, count)...)
		baselineContent := append([]byte{4, 1, 1}, bytes.Repeat([]byte{1, 1, 255}, count)...)
		oldContent = append(oldContent, 5, 0x81, 0)
		baselineContent = append(baselineContent, 5, 0)
		received := append(append([]byte{0x30}, EncodeLength(len(oldContent))...), oldContent...)
		baseline := append(append([]byte{0x30}, EncodeLength(len(baselineContent))...), baselineContent...)
		current := bytes.Clone(baseline)
		current[len(current)-len(baselineContent)+2] = 2
		state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{len(received) - 3}}}
		node := &ReplayNode{state: state, original: received}
		state.root = node
		allocations := testing.AllocsPerRun(3, func() {
			got := replayUnchangedParts(current, node)
			if len(got) != len(current) {
				t.Fatal("length")
			}
		})
		if allocations > float64(4*count+64) {
			t.Fatalf("%d fields: %.0f allocations exceeds linear bound", count, allocations)
		}
		t.Logf("%d fields: %.0f allocations", count, allocations)
	}
}

func TestRepairNestedPartsGrowth(t *testing.T) {
	for _, depth := range []int{32, 64, 128, 256} {
		old := []byte{0x30, 6, 1, 1, 1, 5, 0x81, 0}
		baseline := []byte{0x30, 5, 1, 1, 255, 5, 0}
		for range depth {
			old = append(append([]byte{0x30}, EncodeLength(len(old))...), old...)
			baseline = append(append([]byte{0x30}, EncodeLength(len(baseline))...), baseline...)
		}
		received := append(append([]byte{0x30}, EncodeLength(len(old)+3)...), 4, 1, 1)
		received = append(received, old...)
		base := append(append([]byte{0x30}, EncodeLength(len(baseline)+3)...), 4, 1, 1)
		base = append(base, baseline...)
		current := bytes.Clone(base)
		current[len(current)-len(baseline)-1] = 2
		state := &ReplayState{baselineBytes: base, profileIndex: &replayProfileIndex{offsets: []int{len(received) - 3}}}
		node := &ReplayNode{state: state, original: received}
		state.root = node
		allocations := testing.AllocsPerRun(3, func() {
			got := replayUnchangedParts(current, node)
			if !bytes.Contains(got, []byte{1, 1, 1, 5, 0}) {
				t.Fatal("primitive lost")
			}
		})
		if allocations > float64(30*depth+200) {
			t.Fatalf("depth %d: %.0f allocations exceeds linear bound", depth, allocations)
		}
		t.Logf("depth %d: %.0f allocations", depth, allocations)
	}
}

// A field edit must not discard unrelated primitive padding from the same
// EXTERNAL snapshot. Its original long header itself is repaired.
func TestExternalPrimitiveRepair(t *testing.T) {
	original := repairHex(t, "28810806022a03820207ff")
	value, _, err := DecodeExternal(original)
	if err != nil {
		t.Fatal(err)
	}
	value.DirectReference = runtime.MustObjectIdentifier("1.2.4")
	opts := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true}, rebuildChildren: true}}
	encoded, err := EncodeExternal(value, opts...)
	if err != nil || !bytes.Equal(encoded, repairHex(t, "280806022a04820207ff")) {
		t.Fatalf("%x %v", encoded, err)
	}
	value.Arbitrary.Bytes[0] = 0
	encoded, err = EncodeExternal(value, opts...)
	if err != nil || !bytes.Equal(encoded, repairHex(t, "280806022a0482020700")) {
		t.Fatalf("edited bits %x %v", encoded, err)
	}
	encoded, err = EncodeExternal(value, WithoutBERReplay())
	if err != nil || !bytes.Equal(encoded, repairHex(t, "280806022a0482020700")) {
		t.Fatalf("fresh bits %x %v", encoded, err)
	}
}

// Arbitrary EXTERNAL bits stay opaque even when their octets resemble a TLV.
func TestEditedArbitraryStaysOpaque(t *testing.T) {
	value, _, err := DecodeExternal(repairHex(t, "28810a06022a038204078101ff"))
	if err != nil {
		t.Fatal(err)
	}
	value.Arbitrary.Bytes = []byte{1, 128}
	value.Arbitrary.BitLength = 9
	opts := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true}, rebuildChildren: true}}
	got, err := EncodeExternal(value, opts...)
	want := repairHex(t, "280906022a038203070180")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("opaque bits changed: %x want %x: %v", got, want, err)
	}
}

// X.690 (02/2021) §§8.7, 8.23.3 permit the descriptor's constructed form.
func TestExternalDescriptorFormRepair(t *testing.T) {
	value, _, err := DecodeExternal(repairHex(t, "28810d06022a03270304014181024243"))
	if err != nil {
		t.Fatal(err)
	}
	value.DirectReference = runtime.MustObjectIdentifier("1.2.4")
	opts := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true}, rebuildChildren: true}}
	got, err := EncodeExternal(value, opts...)
	want := repairHex(t, "280d06022a04270304014181024243")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("descriptor form changed: %x want %x: %v", got, want, err)
	}
}
