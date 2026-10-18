// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_profile.go; SHA-256 cf891f3becb99c79e32988fb49aaaff1b405f67d0a1bd763713f5d8590ff8272.
package ber

import (
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"slices"
)

// The outer profile scan precedes child capture. Its located records identify
// exactly which received subtrees must be rebuilt after an edit. Value and
// text rules still run on the whole current value before any strict replay.
// Q.773 (06/1997) §§4.1.1, 4.2.2.2, 4.2.3.
type replayProfileIndex struct {
	offsets   []int
	unknown   bool
	nodes     map[*ReplayNode]int
	baselines map[*ReplayNode][]byte
}

func isTCAPProfileViolation(record Violation) bool {
	return record.Rule.Document == "ITU-T Q.773" && record.Rule.Clause == "4.1.1"
}

func (node *ReplayNode) canReplayProfile() bool {
	return node.state == nil || !node.state.decodeTolerant || node.profileReplaySafe
}

func replayProfileSafe(data []byte, config decodeConfig, node *ReplayNode) bool {
	if config.reportScope == nil || config.location == nil || len(data) == 0 {
		return false
	}
	// Resolve only tolerant capture locations. Successful strict decoding keeps
	// lazy locations and does not construct an index.
	start, ok := config.location.wireOffset(data)
	if !ok {
		return false
	}
	last, ok := config.location.wireOffset(data[len(data)-1:])
	if !ok || last < start {
		return false
	}
	scope := config.reportScope
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if scope.replayProfile == nil {
		index := new(replayProfileIndex)
		for _, record := range scope.ledger.records {
			if !isTCAPProfileViolation(record) {
				continue
			}
			if record.Offset == nil {
				index.unknown = true
				continue
			}
			index.offsets = append(index.offsets, *record.Offset)
		}
		// Reports normally arrive in wire order. Sorting also covers a public
		// helper that appends a later profile finding before an earlier one.
		slices.Sort(index.offsets)
		scope.replayProfile = index
	}
	index := scope.replayProfile
	if len(scope.ledger.records) != 0 {
		if index.nodes == nil {
			index.nodes = make(map[*ReplayNode]int)
		}
		index.nodes[node] = start
	}
	if index.unknown {
		return false
	}
	pos, _ := slices.BinarySearch(index.offsets, start)
	return pos == len(index.offsets) || index.offsets[pos] > last
}

// EXTERNAL retains its own detached bytes rather than a generated ReplayNode.
// In a strict edited operation, validate that complete candidate span with
// its schema boundary before reusing it. This never admits a comparison copy
// or WithoutBERReplay. X.690 (02/2021) §8.18; Q.773 (06/1997) §4.1.1.
func replayExternalForm(value runtime.External, options []EncodeOption) []byte {
	enabled := BERReplayEnabled(options)
	if !enabled {
		config, err := encodeOptions(options)
		if err != nil || config.noReplay || config.tolerant {
			return nil
		}
		edited := false
		for _, option := range options {
			if mode, ok := option.(replayModeOption); ok {
				if mode.collector != nil || mode.comparison || mode.baseline {
					return nil
				}
				edited = edited || mode.rebuildChildren
			}
		}
		if !edited {
			return nil
		}
	}
	original := value.UnchangedBER()
	if original == nil {
		return nil
	}
	if enabled || ValidateBERElement(original, encodingStructureOption(original), tcapEncodedProfileOption{kind: "External"}) == nil {
		return original
	}
	return nil
}
