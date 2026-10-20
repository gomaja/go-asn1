// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/selective_replay_test.go; SHA-256 9e63c76443fefd85e36131a2ecaa1f7bb21559c22f2c647579582d0f202ec1d4.
package ber

import (
	"bytes"
	"reflect"
	"testing"
)

func TestMAPSelectiveChildReplayPaths(t *testing.T) {
	// TS 29.002 V19.1.0 §17.1.1 marks only the OCTET STRING's
	// nonminimal header dirty; X.690 (02/2021) §8.1.3.6 allows the
	// clean indefinite sibling to remain byte-exact.
	state := &ReplayState{decodeTolerant: true, mapViolations: true, profileIndex: &replayProfileIndex{offsets: []int{8}}}
	root := &ReplayNode{state: state, original: []byte{0x30, 12, 0x30, 0x80, 5, 0, 0, 0, 4, 0x81, 1, 7, 5, 0}}
	clean := &ReplayNode{state: state, original: root.original[2:8]}
	dirty := &ReplayNode{state: state, original: root.original[8:12]}
	state.root = root
	for _, row := range []struct {
		name  string
		node  *ReplayNode
		fresh []byte
		want  bool
	}{
		{"clean", clean, []byte{0x30, 2, 5, 0}, true},
		{"dirty", dirty, []byte{4, 1, 7}, false},
	} {
		for _, path := range []string{"linear", "typed", "compared", "fast", "prepared-typed", "prepared-fast"} {
			t.Run(path+"/"+row.name, func(t *testing.T) {
				mode := replayModeOption{state: state, top: root, rebuildChildren: true, strict: true}
				comparisons := new(BERReplayComparisons)
				comparisons.put(reflect.ValueOf(row.node).Pointer(), berValueEqual)
				switch path {
				case "typed", "prepared-typed":
					mode.typed = comparisons
				case "compared", "linear":
					mode.unchanged = map[*ReplayNode]bool{row.node: true}
				case "fast", "prepared-fast":
					identifier, _, err := DecodeTag(row.fresh)
					if err != nil {
						t.Fatal(err)
					}
					state.baselineBytes = row.fresh
					state.baselineNodes = map[*ReplayNode]*replayRecord{row.node: {start: 0, end: len(row.fresh), canonicalTag: identifier, tagKnown: true}}
					mode.fast = &replayFastState{state: state, root: root, nodeValues: comparisons, stack: []replayFastFrame{{node: row.node}}}
				}
				options := []EncodeOption{mode}
				var got []byte
				var replayed bool
				switch path {
				case "linear":
					got, replayed = ReplayGeneratedBERNode(row.node, options)
				case "prepared-typed", "prepared-fast":
					got, replayed = PreparedBERReplay(row.node, options)
				default:
					got = PreserveEncodedBERNode(row.fresh, row.node, options)
					replayed = bytes.Equal(got, row.node.original)
				}
				if replayed != row.want || replayed && !bytes.Equal(got, row.node.original) {
					t.Fatalf("replayed=%v want=%v bytes=%x", replayed, row.want, got)
				}
			})
		}
	}
}
