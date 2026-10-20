// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_unknown_test.go; SHA-256 84d0faeaea5af802b9afd3845b6006ba222508b469c8b477e7ec6b5c1c5c1750.
package ber

import (
	"bytes"
	"testing"
)

func TestMAPRepairUnknownValueComparisonUsesCompleteStream(t *testing.T) {
	// An opaque value's typed comparison can be inconclusive. Its comparison
	// stream still establishes an edit, so strict encoding repairs §17.1.1
	// findings while preserving the legal TRUE octet (X.690 §8.2.2).
	received := structureWire(t, "300701010104810141")
	baseline := structureWire(t, "30060101ff040141")
	current := structureWire(t, "30060101ff040142")
	state := &ReplayState{decodeTolerant: true, mapViolations: true, eagerBaseline: true,
		baselineBytes: baseline, profileIndex: &replayProfileIndex{offsets: []int{5}}}
	node := &ReplayNode{state: state, original: received}
	state.root = node
	state.baselineNodes = map[*ReplayNode]*replayRecord{node: {start: 0, end: len(baseline)}}
	state.same = func(any, *BERReplayComparisons) berValueComparison { return berValueUnknown }
	compared := false
	canonical := func(option EncodeOption) ([]byte, error) {
		mode := option.(replayModeOption)
		if mode.comparison && !mode.diagnostic {
			compared = true
		}
		return current, nil
	}
	options, err := PrepareBERReplay(node, nil, canonical, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if !compared {
		t.Fatal("unknown tolerant root bypassed complete comparison")
	}
	got := PreserveEncodedBERNode(current, node, options)
	want := structureWire(t, "3006010101040142")
	if !bytes.Equal(got, want) {
		t.Fatalf("unknown root repair=%x want=%x", got, want)
	}
	if err := ValidateBERElement(got); err != nil {
		t.Fatal(err)
	}
}
