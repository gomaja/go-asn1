// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_profile_position_test.go; SHA-256 e34fa85228067fce9ea4a28e99dded830185dbd99eb28e49c5da407ee0af7f50.
package ber

import (
	"bytes"
	"testing"
)

func TestMAPReplayPositionUsesDecodeLocation(t *testing.T) {
	// The IMPLICIT identifier replaces three physical octets with one in the
	// child's private buffer (X.690 (02/2021) §8.14.4). Equal-valued siblings
	// must still resolve to their individual received occurrences.
	wire := structureWire(t, "300ebf810003010101bf810003010101")
	root := &ReplayNode{original: wire}
	state := &ReplayState{root: root}
	pending := &mapProfileState{}
	for _, start := range []int{2, 9} {
		reconstructed := structureWire(t, "3003010101")
		origin := &decodeOrigin{root: wire}
		location := &decodeLocation{origin: origin, input: reconstructed, offset: start}
		node := &ReplayNode{state: state, original: reconstructed}
		captureReplayProfilePosition(reconstructed, decodeConfig{tolerant: true, form: &berFormState{mapSyntax: mapSyntaxGenerated, mapPending: pending}, location: location}, node)
		state.profileIndex = &replayProfileIndex{offsets: []int{start + 7}}
		if offset, ok := replayNodeOffset(node); !ok || offset != start {
			t.Fatalf("occurrence=%d got %d/%v", start, offset, ok)
		}
		if !node.canReplayProfile() {
			t.Fatal("finding at following sibling dirtied the node")
		}
		state.profileIndex.offsets = []int{start + 6}
		if node.canReplayProfile() {
			t.Fatal("last physical octet's finding lost under retag")
		}
	}
}

func TestMAPReplayIndexExcludesOpaqueFindings(t *testing.T) {
	// Decision B: a foreign open value owns its complete encoding (X.690
	// (02/2021) §8.15), even when another MAP-owned header violates §17.1.1.
	form := &berFormState{mapSyntax: mapSyntaxGenerated, mapPending: &mapProfileState{
		offsets: []int{0, 4}, byOffset: map[int]*mapProfileElement{
			0: {owned: true, rules: mapShortLength}, 4: {rules: mapShortLength},
		},
	}}
	index := mapReplayProfileIndex(form)
	if index == nil || len(index.offsets) != 1 || index.offsets[0] != 0 {
		t.Fatalf("index=%+v", index)
	}
	received := structureWire(t, "30810404810141")
	baseline := structureWire(t, "300404810141")
	state := &ReplayState{profileIndex: index, baselineBytes: baseline}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	if got := replayUnchangedParts(baseline, node); !bytes.Equal(got, baseline) {
		t.Fatalf("opaque header repaired: %x", got)
	}
}

func TestMAPReplayPositionBeforeFirstFinding(t *testing.T) {
	wire := structureWire(t, "3006a08005000000")
	root := &ReplayNode{original: wire}
	state := &ReplayState{root: root}
	data := structureWire(t, "308005000000")
	node := &ReplayNode{state: state, original: data}
	config := decodeConfig{tolerant: true, form: &berFormState{mapSyntax: mapSyntaxGenerated}, location: &decodeLocation{origin: &decodeOrigin{root: wire}, input: data, offset: 2}}
	captureReplayProfilePosition(data, config, node)
	// The typed decoder discovers the first IMPLICIT-string finding later.
	state.profileIndex = &replayProfileIndex{offsets: []int{8}}
	if off, ok := replayNodeOffset(node); !ok || off != 2 {
		t.Fatalf("earlier clean node lost: %d %v", off, ok)
	}
}

func TestMAPReplayEmptyImplicitIdentifierWidth(t *testing.T) {
	wire := structureWire(t, "3004bf810000")
	root := &ReplayNode{original: wire}
	state := &ReplayState{root: root, profileIndex: new(replayProfileIndex)}
	node := &ReplayNode{state: state, original: []byte{0x30, 0}, profileLocation: &decodeLocation{origin: &decodeOrigin{root: wire}, input: []byte{0x30, 0}, offset: 2}}
	position, ok := replayNodePosition(node)
	if !ok || position.offset != 2 || position.tagDelta != 2 {
		t.Fatalf("empty IMPLICIT position=%+v/%v", position, ok)
	}
}
