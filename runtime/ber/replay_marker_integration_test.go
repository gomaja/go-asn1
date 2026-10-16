package ber

import (
	"bytes"
	"testing"
)

func TestPrepareBERReplayGeneratedMarkerUsesStrictTypedReturn(t *testing.T) {
	for _, eager := range []bool{false, true} {
		name := "lazy-baseline"
		if eager {
			name = "eager-baseline"
		}
		t.Run(name, func(t *testing.T) {
			state := &ReplayState{nodeCount: 1, eagerBaseline: eager}
			node := &ReplayNode{state: state, original: []byte{4, 1, 'A'}}
			state.root = node
			state.same = func(any, *replayNodeComparisons) berValueComparison { return berValueDifferent }
			if eager {
				state.baselineNodes = map[*ReplayNode]*replayRecord{node: {}}
			}
			comparisonEncodes := 0
			options, err := PrepareBERReplay(node, []EncodeOption{generatedEncodeMarker{}}, func(EncodeOption) ([]byte, error) {
				comparisonEncodes++
				return nil, ErrInvalidValue
			}, nil)
			if err != nil || comparisonEncodes != 0 {
				t.Fatalf("typed return: comparisons = %d, error = %v", comparisonEncodes, err)
			}
			if len(options) != 1 {
				t.Fatalf("prepared options = %d, want one replay mode", len(options))
			}
			if _, ok := options[0].(replayModeOption); !ok {
				t.Fatalf("prepared option = %T, want replay mode", options[0])
			}
			got := PreserveEncodedBERNode([]byte{4, 1, 'B'}, node, options)
			if !bytes.Equal(got, []byte{4, 1, 'B'}) {
				t.Fatalf("changed value = %x, want 040142", got)
			}
		})
	}
}

func TestPrepareBERReplayGeneratedMarkerWithLongLengthUsesTypedReturn(t *testing.T) {
	state := &ReplayState{nodeCount: 1, eagerBaseline: true}
	node := &ReplayNode{state: state, original: []byte{4, 0x81, 1, 'A'}}
	state.root = node
	state.baselineNodes = map[*ReplayNode]*replayRecord{node: {}}
	state.same = func(any, *replayNodeComparisons) berValueComparison { return berValueDifferent }
	comparisonEncodes := 0
	options, err := PrepareBERReplay(node, []EncodeOption{generatedEncodeMarker{}}, func(EncodeOption) ([]byte, error) {
		comparisonEncodes++
		return nil, ErrInvalidValue
	}, nil)
	if err != nil || comparisonEncodes != 0 {
		t.Fatalf("typed return: comparisons = %d, error = %v", comparisonEncodes, err)
	}
	got := PreserveEncodedBERNode([]byte{4, 1, 'B'}, node, options)
	if !bytes.Equal(got, []byte{4, 1, 'B'}) {
		t.Fatalf("changed value = %x, want 040142", got)
	}
}
