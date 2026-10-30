// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/tcap_segmented.go; SHA-256 be5a8f18a8c3e6a3142bab332e13ecdc19d4852e38dec22a5bb64e8fdf72fcbe.
package ber

import (
	"fmt"
	"math"
	"slices"
)

// Q.773 (06/1997) §§3.2, 4.1.1, 4.2.3; X.690 (02/2021)
// §§8.6.4, 8.7.3, 8.18.10–8.18.11. One flat destination and one wire
// position per reassembled octet avoid copying nested prefixes repeatedly.
// ChildIndexes retain the choice's wire ancestry followed by the APDU's
// logical ancestry, without segment indexes: segmentation has no semantics.
type dialogueSegments struct {
	contents []byte
	offsets  []int
	prefix   []int
	path     string
	syntax   int
	replay   *replayProfileIndex
}

func (segments *dialogueSegments) append(contents []byte, offset int) {
	segments.contents = append(segments.contents, contents...)
	for index := range contents {
		segments.offsets = append(segments.offsets, offset+index)
	}
}

// This private option returns the work actually spent by a subscan to its
// caller. The caller subtracts it from the same aggregate work/element budget.
// No decodeConfig or ordinary scan frame needs additional storage.
type dialogueScanOption struct {
	config  decodeConfig
	collect *dialogueSegments
	positionSearch
}

func (option *dialogueScanOption) applyDecode(config *decodeConfig) error {
	*config = option.config
	if option.target == 0 {
		option.target = math.MaxInt
	}
	option.positionSearch.segments = option.collect
	config.positionSearch = &option.positionSearch
	return nil
}

func (segments *dialogueSegments) audit(data []byte, config decodeConfig, options []DecodeOption, stack []berScanFrame, work, elements int) (int, int, error) {
	if work <= 0 || elements <= 0 || len(stack) >= config.limits.MaxDepth {
		return 0, 0, fmt.Errorf("%w: reassembled dialogue scan budget exhausted", ErrResourceLimit)
	}
	// Logical ancestry has one entry per enclosing scan frame.
	segments.prefix = make([]int, 0, len(stack))
	segments.path = qualifyConstraintPath(options, "")
	parentType := tcapKindUnknown
	for index, ancestor := range stack[1:] {
		identifier, _, _ := DecodeTag(data[ancestor.offset:])
		segment := tcapPathSegment(config.profileType, parentType, ancestor.profileType, identifier, ancestor.index, index == 0)
		if segment != "" {
			if segments.path != "" {
				segments.path += "."
			}
			segments.path += segment
		}
		parentType = ancestor.profileType
		if index > 0 {
			segments.prefix = append(segments.prefix, ancestor.index)
		}
	}
	// The final stack frame is EXTERNAL, whose next child was this choice.
	segments.prefix = append(segments.prefix, stack[len(stack)-1].nextChild-1, 0)
	identifier, _, err := DecodeTag(segments.contents)
	if err != nil {
		// A partial root identifier has no scan yet. Locate its first octet,
		// even across segments (X.690 (02/2021) §8.1.2.4.2 and Erratum 1
		// (09/2021, Figure 4)); an empty APDU has no identifier to locate.
		if len(segments.offsets) == 0 {
			return 0, 0, err
		}
		offset := segments.offsets[0]
		if config.location != nil {
			if absolute, ok := config.location.wireOffset(data[offset:]); ok {
				offset = absolute
			}
		}
		return 0, 0, &ElementError{offset: offset, childIndexes: segments.prefix, cause: err}
	}
	contentType := tcapKindDialogueContent
	if segments.syntax == 2 {
		contentType = tcapKindUniDialogueContent
	}
	kind := tcapElementType(tcapKindUnknown, contentType, identifier, 0, false, segments.syntax)
	segment := tcapPathSegment("", contentType, kind, identifier, 0, false)
	if segments.path != "" {
		segments.path += "."
	}
	segments.path += segment
	if config.location != nil {
		for i, offset := range segments.offsets {
			if absolute, ok := config.location.wireOffset(data[offset:]); ok {
				segments.offsets[i] = absolute
			}
		}
	}
	return segments.scan(config, work, elements, len(stack))
}

func (segments *dialogueSegments) scan(config decodeConfig, work, elements, depth int) (int, int, error) {
	origin := &decodeOrigin{root: segments.contents, limits: config.limits, profileType: "DialoguePDU", search: &positionSearch{segments: segments}}
	location := &decodeLocation{origin: origin, input: segments.contents, offset: segments.offsets[0]}
	config.location = location
	config.profileNested = false
	config.profileType = "DialoguePDU"
	if segments.syntax == 2 {
		config.profileType = "UniDialoguePDU"
		origin.profileType = config.profileType
	}
	config.limits.MaxWork = work
	config.limits.MaxElements = elements
	config.limits.MaxDepth -= depth
	config.form = nil
	option := &dialogueScanOption{config: config}
	err := ValidateBERElement(segments.contents, option)
	return option.work, option.elements, err
}

func (segments *dialogueSegments) ancestry(origin *decodeOrigin, target int) ([]int, error) {
	offset, ok := slices.BinarySearch(segments.offsets, target)
	if !ok {
		return nil, nil
	}
	copyOrigin := *origin
	search := *origin.search
	copyOrigin.search = &search
	copyOrigin.search.segments = nil
	indexes, err := copyOrigin.ancestry(offset)
	origin.search, origin.located, origin.ancestryVisits = copyOrigin.search, copyOrigin.located, copyOrigin.ancestryVisits
	// Retain provenance while the copied cursor walks logical APDU offsets.
	origin.search.segments = segments
	return append(append([]int(nil), segments.prefix...), indexes...), err
}

// DecodeExternal has already bounded and validated these string segments.
// Reuse the linear scanner to reconstruct their position map; no recursive
// concatenation or per-segment ancestry lookup is necessary.
func locateSegmentedDialogue(choice, inner []byte, config decodeConfig, options []DecodeOption) []DecodeOption {
	segments := new(dialogueSegments)
	collectConfig := config
	collectConfig.profile = false
	collectConfig.form = nil
	collectConfig.location = nil
	collectConfig.collectPositionsOnly = true
	collect := &dialogueScanOption{config: collectConfig, collect: segments}
	// The context tag is IMPLICIT: the collector needs its string kind.
	wire := append([]byte(nil), choice...)
	if wire[0]&31 == 1 {
		wire[0] = 0x24
	} else {
		wire[0] = 0x23
	}
	if err := ValidateBERElement(wire, collect); err != nil {
		return options
	}
	base, ok := config.location.wireOffset(choice)
	if !ok {
		return options
	}
	for i := range segments.offsets {
		segments.offsets[i] += base
	}
	segments.contents = inner
	if len(segments.offsets) != len(inner) || len(inner) == 0 {
		return options
	}
	segments.prefix, _ = config.location.decodeOrigin().ancestry(base)
	segments.prefix = append(segments.prefix, 0)
	origin := &decodeOrigin{root: inner, limits: config.limits, profileType: config.profileType, search: &positionSearch{segments: segments}}
	location := &decodeLocation{origin: origin, input: inner, offset: segments.offsets[0], source: "DialoguePortion"}
	if len(options) == 1 {
		if parent, ok := options[0].(*generatedDecodeOption); ok {
			storage := new(generatedDecodeContextStorage)
			storage.context = *parent
			storage.context.location = *location
			storage.context.config.location = &storage.context.location
			storage.options[0] = &storage.context
			return storage.options[:]
		}
	}
	return append(options[:len(options):len(options)], decodeLocationOption{location})
}

// Translate the sorted retained findings and the ordered segment map together.
// This runs once per reassembled APDU, never once per segment or replay node.
// Findings on the EXTERNAL envelope and string headers remain in the wire index.
func (segments *dialogueSegments) replayIndex(wire *replayProfileIndex) *replayProfileIndex {
	if segments.replay == nil {
		logical := &replayProfileIndex{unknown: wire.unknown}
		cursor, _ := slices.BinarySearch(wire.offsets, segments.offsets[0])
		for offset, received := range segments.offsets {
			for cursor < len(wire.offsets) && wire.offsets[cursor] < received {
				cursor++
			}
			for cursor < len(wire.offsets) && wire.offsets[cursor] == received {
				logical.offsets = append(logical.offsets, offset)
				cursor++
			}
		}
		segments.replay = logical
	}
	return segments.replay
}
