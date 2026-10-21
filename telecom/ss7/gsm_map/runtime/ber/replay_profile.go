// Code generated from MAP runtime source. DO NOT EDIT.

// Runtime source: runtime/ber/replay_profile.go; SHA-256 324322f03c8855541de8a1fc3e1cfb934f9e4d5cbbe80351fa8d708ff4c0a588.
package ber

import (
	"slices"
	"sync"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
)

// Only retained findings on MAP-defined syntax can make a received span
// unsafe. X.690 (02/2021) §8.15 leaves open values to their own syntax;
// TS 29.002 V19.1.0 §17.1.1 governs the claimed MAP headers and strings.
type replayProfileIndex struct {
	offsets   []int
	mu        sync.Mutex
	unknown   bool
	baselines map[*ReplayNode][]byte
}

func mapReplayProfileIndex(form *berFormState) *replayProfileIndex {
	if form == nil || !form.mapProfile() || form.mapPending == nil {
		return nil
	}
	index := new(replayProfileIndex)
	for _, offset := range form.mapPending.offsets {
		if element := form.mapPending.byOffset[offset]; element != nil && element.owned && element.rules != 0 {
			index.offsets = append(index.offsets, offset)
		}
	}
	if len(index.offsets) == 0 {
		return nil
	}
	slices.Sort(index.offsets)
	return index
}

func (node *ReplayNode) canReplayProfile() bool {
	if node.state == nil || node.state.profileIndex == nil {
		return true
	}
	position, ok := replayNodePosition(node)
	start := position.offset
	if !ok {
		return false
	}
	index := node.state.profileIndex
	pos, _ := slices.BinarySearch(index.offsets, start)
	return pos == len(index.offsets) || index.offsets[pos]-start >= len(node.original)+position.tagDelta
}

// A reconstructed IMPLICIT identifier can have a different width from the
// received one. The location maps its contents back to the physical input;
// equal sibling octets never establish an occurrence. X.690 (02/2021) §8.14.
type replayProfilePosition struct {
	offset   int
	tagDelta int
}

func captureReplayProfilePosition(data []byte, config decodeConfig, node *ReplayNode) {
	// Retain the existing lazy location even before the first finding: an
	// IMPLICIT string may be identified only by a later typed decoder. Valid
	// values never resolve it or allocate a profile index.
	if config.tolerant && config.form != nil && config.form.mapProfile() && len(data) != 0 {
		node.profileLocation = config.location
	}
}

func replayNodePosition(node *ReplayNode) (replayProfilePosition, bool) {
	if node == nil || node.state == nil || node.state.root == nil || len(node.original) == 0 {
		return replayProfilePosition{}, false
	}
	if index := node.state.profileIndex; index != nil && node.profileLocation != nil {
		// Concurrent encodes share the immutable decode tree. Only this failed
		// profile path resolves its lazy locations, under the index's lock.
		index.mu.Lock()
		defer index.mu.Unlock()
		if node.profilePositionKnown {
			return node.profilePosition, true
		}
		location := node.profileLocation
		data := location.input
		if len(node.original) > len(data) {
			return replayProfilePosition{}, false
		}
		start, ok := location.wireOffset(data)
		if !ok {
			return replayProfilePosition{}, false
		}

		// Even an empty value has a length octet: its last byte may still
		// be in the reconstructed header, so compare identifier widths
		// directly instead of locating that byte (X.690 §8.14.4).
		_, receivedTagLength, err := DecodeTag(location.rootInput()[start:])
		if err != nil {
			return replayProfilePosition{}, false
		}
		_, ownTagLength, err := DecodeTag(data)
		if err != nil {
			return replayProfilePosition{}, false
		}
		node.profilePosition = replayProfilePosition{offset: start, tagDelta: receivedTagLength - ownTagLength}
		node.profilePositionKnown = true
		return node.profilePosition, true
	}
	// Hand-written runtime users without a generated location can still prove
	// an occurrence through the received backing array.
	offset, ok := berSubsliceOffset(node.state.root.original, node.original)
	return replayProfilePosition{offset: offset}, ok
}

func replayNodeOffset(node *ReplayNode) (int, bool) {
	position, ok := replayNodePosition(node)
	return position.offset, ok
}

// EXTERNAL owns its framing and typed alternatives but not the complete
// single-ASN1-type value (X.690 (02/2021) §§8.15, 8.18). Its detached
// snapshot is checked before a strict edited replay can reuse it.
func replayExternalForm(value runtime.External, options []EncodeOption) []byte {
	if !mapReplayProfileEnabled(options) {
		if BERReplayEnabled(options) {
			return value.UnchangedBER()
		}
		return nil
	}
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
	if enabled {
		return original
	}
	part := replayPartRoot(original)
	if part == nil {
		return nil
	}
	index := new(replayProfileIndex)
	collectReplayPartViolations(part, index, true, false)
	if len(index.offsets) == 0 {
		return original
	}
	return nil
}

func mapReplayProfileEnabled(options []EncodeOption) bool {
	for _, option := range options {
		switch value := option.(type) {
		case mapGenericEncodeOption:
			return false
		case replayModeOption:
			return value.state != nil && value.state.mapProfileChecked
		}
	}
	return false
}
