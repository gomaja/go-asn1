// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/selective_replay_test.go; SHA-256 4aa982bb674df16d6b50e1cf3f1bb0e83f7b9a0c7dfb19916985c8fef59ccfac.
package ber

import (
	"bytes"
	"reflect"
	"testing"
)

// Q.773 (06/1997) §4.1.1 refuses the long length but permits the
// sibling's indefinite constructed form (X.690 (02/2021) §8.1.3.6).
func TestSelectiveReceivedReplay(t *testing.T) {
	wire := []byte{0x30, 12, 0x30, 0x80, 5, 0, 0, 0, 4, 0x81, 1, 7, 5, 0}
	var config decodeConfig
	var log ViolationLog
	opts, commit := StageDecodeReports([]DecodeOption{WithTolerance(&log)})
	defer commit(true)
	var err error
	config, err = decodeOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	bad := identifyViolation(Violation{Constraint: "Q.773 §4.1.1: short-length", Offset: new(8), Path: "bad", scope: config.reportScope})
	if err := config.violations.append(bad, config.diagnostics); err != nil {
		t.Fatal(err)
	}
	state := &ReplayState{decodeTolerant: true}
	source := &validatedBERSource{owned: wire, replay: state}
	config.location = &decodeLocation{origin: &decodeOrigin{root: wire}, input: wire}
	context := &generatedDecodeOption{source: source, config: config}
	clean := CaptureGeneratedBERReplay(wire[2:8], []DecodeOption{context})
	dirty := CaptureGeneratedBERReplay(wire[8:12], []DecodeOption{context})
	root := &ReplayNode{state: state, original: wire}
	state.root = root
	for _, node := range []*ReplayNode{clean, dirty} {
		for _, path := range []string{"linear", "typed", "compared", "fast", "prepared-typed", "prepared-fast"} {
			name := "dirty"
			if node == clean {
				name = "clean"
			}
			t.Run(path+"/"+name, func(t *testing.T) {
				fresh := []byte{0x30, 2, 5, 0}
				if node == dirty {
					fresh = []byte{4, 1, 7}
				}
				mode := replayModeOption{state: state, top: root, rebuildChildren: true, strict: true}
				comparisons := new(BERReplayComparisons)
				comparisons.put(reflect.ValueOf(node).Pointer(), berValueEqual)
				switch path {
				case "typed", "prepared-typed":
					mode.typed = comparisons
				case "compared", "linear":
					mode.unchanged = map[*ReplayNode]bool{node: true}
				case "fast", "prepared-fast":
					identifier, _, err := DecodeTag(fresh)
					if err != nil {
						t.Fatal(err)
					}
					state.baselineBytes = fresh
					state.baselineNodes = map[*ReplayNode]*replayRecord{node: {start: 0, end: len(fresh), canonicalTag: identifier, tagKnown: true}}
					mode.fast = &replayFastState{state: state, root: root, nodeValues: comparisons, stack: []replayFastFrame{{node: node}}}
				}
				options := []EncodeOption{mode}
				var got []byte
				var replay bool
				switch path {
				case "linear":
					got, replay = ReplayGeneratedBERNode(node, options)
				case "prepared-typed", "prepared-fast":
					got, replay = PreparedBERReplay(node, options)
				default:
					got = PreserveEncodedBERNode(fresh, node, options)
					replay = bytes.Equal(got, node.original)
				}
				wantReplay := node == clean
				if replay != wantReplay {
					t.Fatalf("replayed=%v want %v: %x", replay, wantReplay, got)
				}
				if replay && !bytes.Equal(got, node.original) {
					t.Fatalf("received bytes changed %x", got)
				}
			})
		}
	}
}

func TestSelectiveExternalReplay(t *testing.T) {
	for _, row := range []struct {
		name   string
		wire   []byte
		replay bool
	}{
		{"clean-indefinite", []byte{0x28, 0x80, 6, 2, 42, 3, 0x81, 1, 65, 0, 0}, true},
		{"long-length", []byte{0x28, 0x81, 7, 6, 2, 42, 3, 0x81, 1, 65}, false},
		{"constructed-octets", []byte{0x28, 11, 6, 2, 42, 3, 0xa1, 0x80, 4, 1, 65, 0, 0}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			value, _, err := DecodeExternal(row.wire)
			if err != nil {
				t.Fatal(err)
			}
			opts := []EncodeOption{replayModeOption{state: &ReplayState{decodeTolerant: true}, rebuildChildren: true}}
			got, err := EncodeExternal(value, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, row.wire) != row.replay {
				t.Fatalf("received form: %x replay=%v", got, row.replay)
			}
			if err := ValidateBERElement(got, tcapEncodedProfileOption{kind: "External"}); err != nil {
				t.Fatal(err)
			}
			// Comparison streams must still rebuild even a clean received EXTERNAL.
			opts = []EncodeOption{replayModeOption{state: new(ReplayState), comparison: true, rebuildChildren: true}}
			got, err = EncodeExternal(value, opts...)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(got, row.wire) {
				t.Fatalf("comparison replayed received form: %x", got)
			}
		})
	}
}

// An indefinite container is compliant with Q.773 (06/1997) §4.1.1.
// Its form preference is independent of whether a descendant needs repair,
// while baseline and comparison streams must rebuild consistently.
func TestContainerFormReplayPolicy(t *testing.T) {
	state := new(ReplayState)
	for _, row := range []struct {
		name    string
		mode    replayModeOption
		enabled bool
	}{
		{"edited", replayModeOption{state: state, rebuildChildren: true}, true},
		{"comparison", replayModeOption{state: state, comparison: true}, false},
		{"baseline", replayModeOption{state: state, baseline: true}, false},
		{"collector", replayModeOption{state: state, collector: new(replayCollector)}, false},
	} {
		if got := BERGeneratedReplayEnabled([]EncodeOption{row.mode}); got != row.enabled {
			t.Errorf("%s: enabled=%v want %v", row.name, got, row.enabled)
		}
	}
}

func TestSelectiveReplayUsesSourceProofs(t *testing.T) {
	for _, clean := range []bool{false, true} {
		state := &ReplayState{decodeTolerant: true, generatedComparison: true, nodeCount: 2}
		child := &ReplayNode{state: state, original: []byte{0x30, 0x80, 5, 0, 0, 0}, profileReplaySafe: clean}
		root := &ReplayNode{state: state, original: []byte{0x30, 8, 0x30, 0x80, 5, 0, 0, 0, 5, 0}}
		state.root = root
		state.same = func(_ any, nodes *BERReplayComparisons) berValueComparison {
			nodes.Record(root, root, int(berValueDifferent))
			nodes.Record(child, child, int(berValueUnknown), func() bool { return true })
			return berValueDifferent
		}
		options, err := PrepareBERReplay(root, nil, func(EncodeOption) ([]byte, error) { return []byte{0x30, 6, 0x30, 2, 5, 0, 5, 0}, nil }, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, replayed := ReplayGeneratedBERNode(child, options)
		if replayed != clean {
			t.Fatalf("clean=%v replayed=%v: %x", clean, replayed, got)
		}
	}
}
