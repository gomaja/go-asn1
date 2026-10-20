// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_parts_test.go; SHA-256 9a19571c98d083c75616d2e41522ad3fc76ce716888a970555113cb210fbf400.
package ber

import (
	"bytes"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// TS 29.002 V19.1.0 §17.1.1 repairs the nonminimal length, while
// X.690 (02/2021) §8.2.2 permits the clean BOOLEAN TRUE octet to remain 01.
func TestMAPRepairKeepsCleanPrimitiveAfterEdit(t *testing.T) {
	received := []byte{0x30, 9, 1, 1, 1, 4, 1, 1, 5, 0x81, 0}
	baseline := []byte{0x30, 8, 1, 1, 0xff, 4, 1, 1, 5, 0}
	current := []byte{0x30, 8, 1, 1, 0xff, 4, 1, 2, 5, 0}
	state := &ReplayState{decodeTolerant: true, mapViolations: true, baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{9}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	got := PreserveEncodedBERNode(current, node, []EncodeOption{replayModeOption{state: state, top: node, rebuildChildren: true}})
	want := []byte{0x30, 8, 1, 1, 1, 4, 1, 2, 5, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("selective repair = %x, want %x", got, want)
	}
}

func TestMAPRepairNonminimalContainerHeaderAfterEdit(t *testing.T) {
	// TS 29.002 V19.1.0 §17.1.1 repairs the root's long short length
	// even when an edit leaves its content size unchanged.
	received := []byte{0x30, 0x81, 3, 4, 1, 1}
	baseline := []byte{0x30, 3, 4, 1, 1}
	current := []byte{0x30, 3, 4, 1, 2}
	state := &ReplayState{decodeTolerant: true, mapViolations: true, baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{0}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	got := replayUnchangedParts(current, node)
	if !bytes.Equal(got, current) {
		t.Fatalf("root header = %x, want %x", got, current)
	}
}

func TestMAPExternalKeepsLegalBitPaddingAfterEdit(t *testing.T) {
	// X.690 (02/2021) §§8.6.2.2, 8.18 permit this BER padding;
	// TS 29.002 V19.1.0 §17.1.1 repairs EXTERNAL's own long length.
	original := []byte{0x28, 0x81, 8, 6, 2, 0x2a, 3, 0x82, 2, 7, 0xff}
	value, n, err := DecodeExternal(original)
	if err != nil || n != len(original) {
		t.Fatalf("decode: %d %v", n, err)
	}
	value.DirectReference = runtime.MustObjectIdentifier("1.2.4")
	options := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true, mapProfileChecked: true}, rebuildChildren: true}}
	got, err := EncodeExternal(value, options...)
	want := []byte{0x28, 8, 6, 2, 0x2a, 4, 0x82, 2, 7, 0xff}
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("edited EXTERNAL = %x, want %x: %v", got, want, err)
	}
}

func TestMAPRepairPrimitiveVariants(t *testing.T) {
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

func TestMAPRepairPartsGrowth(t *testing.T) {
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

func TestMAPRepairNestedPartsGrowth(t *testing.T) {
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

func TestMAPRepairRepeatedPrimitiveOccurrences(t *testing.T) {
	// Distinct TRUE octets have the same abstract value (X.690 (02/2021)
	// §8.2.2). Each child keeps its own received form after the sibling edit;
	// matching the first equal-valued sibling again would transfer its form.
	received := structureWire(t, "300c010101010102040101058100")
	baseline := structureWire(t, "300b0101ff0101ff0401010500")
	current := structureWire(t, "300b0101ff0101ff0401020500")
	want := structureWire(t, "300b0101010101020401020500")
	state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{11}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	if got := replayUnchangedParts(current, node); !bytes.Equal(got, want) {
		t.Fatalf("repeated occurrence forms=%x want=%x", got, want)
	}
}

func TestMAPRepairNestedOffsetSkipsPriorFindings(t *testing.T) {
	// The root's earlier §17.1.1 violation cannot dirty the nested node's
	// legal indefinite header (X.690 (02/2021) §8.1.3.6).
	received := structureWire(t, "30810d30800101010581000000040101")
	baseline := structureWire(t, "300a30050101ff0500040101")
	state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{0, 8}}}
	root := &ReplayNode{state: state, original: received}
	state.root = root
	node := &ReplayNode{state: state, original: received[3:13]}
	state.baselineNodes = map[*ReplayNode]*replayRecord{node: {start: 2, end: 9}}
	got := replayUnchangedParts(structureWire(t, "30050101ff0500"), node)
	want := structureWire(t, "308001010105000000")
	if !bytes.Equal(got, want) {
		t.Fatalf("nested repair=%x want=%x", got, want)
	}
}

func TestMAPRepairKeepsEditedForeignHeader(t *testing.T) {
	// The root violates TS 29.002 V19.1.0 §17.1.1; the first child is
	// a foreign open value with a new complete encoding. Decision B and
	// X.690 (02/2021) §8.15 leave its edited header to its own codec.
	received := structureWire(t, "3081050401410500")
	baseline := structureWire(t, "30050401410500")
	current := structureWire(t, "3006048101410500")
	state := &ReplayState{baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{0}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	if got := replayUnchangedParts(current, node); !bytes.Equal(got, current) {
		t.Fatalf("edited foreign header changed: %x want=%x", got, current)
	}
}
