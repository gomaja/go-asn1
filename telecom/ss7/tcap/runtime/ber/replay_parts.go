// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_parts.go; SHA-256 696b15e210fe3e41f86ebb62e4274837848e2d3acaaa3873a55d96959efc04fa.
package ber

import (
	"bytes"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
	"reflect"
	"slices"
)

// A repair compares three streams: the received bytes, the encoding of the
// detached decode-time value, and the encoding of the edited value. The middle
// stream supplies schema-aware primitive equality, including IMPLICIT fields.
// It is never itself replay authority. X.690 (02/2021) §§8.2.2, 8.6.2.2,
// 8.1.3, 8.9.3; Q.773 (06/1997) §4.1.1.
type replayPart struct {
	tag          tag.Tag
	start        int
	header       []byte
	content      []byte
	wire         []byte
	children     []*replayPart
	indefinite   bool
	cleanHeader  bool
	baselineSame bool
	cleanSpan    bool
	boundary     bool
}

// Read each header once. In particular an indefinite parent never rescans its
// descendants to find its end marker. All streams have already been validated
// or produced by the encoder; checks here refuse a mismatched comparison.
// maxReplayPartDepth bounds the recursive walk over a received encoding. A
// caller may raise DecodeLimits.MaxDepth far beyond the default, and encoding
// must never exhaust the goroutine stack: a deeper value is rebuilt in its
// canonical form instead of keeping its received parts.
const maxReplayPartDepth = 10000

func readReplayPart(data []byte, pos *int, depth int) *replayPart {
	if depth > maxReplayPartDepth {
		return nil
	}
	start := *pos
	identifier, tn, err := DecodeTag(data[start:])
	if err != nil {
		return nil
	}
	length, indefinite, ln, err := DecodeLength(data[start+tn:])
	if err != nil || indefinite && !identifier.Constructed {
		return nil
	}
	*pos += tn + ln
	contentStart := *pos
	end := len(data)
	if !indefinite {
		if length > end-contentStart {
			return nil
		}
		end = contentStart + length
	}
	part := &replayPart{tag: identifier, start: start, header: data[start:contentStart], indefinite: indefinite,
		cleanHeader: !tcapProfileViolation(data, start, tn, ln, indefinite, identifier, tcapKindUnknown)}
	if identifier.Constructed {
		for *pos < end {
			if indefinite && end-*pos >= 2 && data[*pos] == 0 && data[*pos+1] == 0 {
				break
			}
			child := readReplayPart(data[:end], pos, depth+1)
			if child == nil {
				return nil
			}
			part.children = append(part.children, child)
		}
	} else {
		*pos = end
	}
	part.content = data[contentStart:*pos]
	if indefinite {
		if end-*pos < 2 || data[*pos] != 0 || data[*pos+1] != 0 {
			return nil
		}
		*pos += 2
	} else if *pos != end {
		return nil
	}
	part.wire = data[start:*pos]
	return part
}

func replayPartRoot(data []byte) *replayPart {
	pos := 0
	part := readReplayPart(data, &pos, 0)
	if pos != len(data) {
		return nil
	}
	return part
}

type replayPartPlan struct {
	header   []byte
	content  []byte
	children []replayPartPlan
	size     int
	eoc      bool
}

// The profile offsets and received nodes are ordered. Charge each offset once,
// including findings inside an encapsulated primitive payload. The header is
// repairable only when the outer Q.773 (06/1997) §4.1.1 scan actually found
// it; X.690 (02/2021) §8.15 leaves foreign headers to their own codec.
func markReplayPartSafety(part *replayPart, index *replayProfileIndex, cursor *int) {
	start := *cursor
	for *cursor < len(index.offsets) && index.offsets[*cursor] < part.start+len(part.header) {
		*cursor++
	}
	part.cleanHeader = *cursor == start
	for _, child := range part.children {
		markReplayPartSafety(child, index, cursor)
	}
	for *cursor < len(index.offsets) && index.offsets[*cursor] < part.start+len(part.wire) {
		*cursor++
	}
	part.cleanSpan = !index.unknown && *cursor == start
}

// Match occurrences within the same parent, never by searching for equal bytes
// in another subtree. TCAP SEQUENCE fields have distinct identifiers; repeated
// component/EXTERNAL nodes have already made their typed replay decisions.
func planReplayParts(received, baseline, current *replayPart) replayPartPlan {
	unchanged := replayPartPlan{content: current.wire, size: len(current.wire)}
	if received == nil || baseline == nil || replayPartTag(received.tag) != replayPartTag(baseline.tag) || baseline.tag != current.tag {
		return unchanged
	}
	if baseline.boundary || received.baselineSame {
		return unchanged
	}
	if !current.tag.Constructed {
		if bytes.Equal(baseline.content, current.content) && received.cleanSpan {
			return replayPartPlan{content: received.wire, size: len(received.wire)}
		}
		// Primitive contents are not implicitly another BER stream. Owned
		// dialogue APDUs have already made their own node-local decisions;
		// foreign octets and bits remain opaque even if they resemble TLVs.
		return unchanged
	}
	old := make(map[tag.Tag][]*replayPart, len(received.children))
	base := make(map[tag.Tag][]*replayPart, len(baseline.children))
	for _, part := range received.children {
		old[replayPartTag(part.tag)] = append(old[replayPartTag(part.tag)], part)
	}
	for _, part := range baseline.children {
		base[replayPartTag(part.tag)] = append(base[replayPartTag(part.tag)], part)
	}
	plans := make([]replayPartPlan, 0, len(current.children))
	size := 0
	for _, part := range current.children {
		plan := replayPartPlan{content: part.wire, size: len(part.wire)}
		// Each EXTERNAL in a collection repairs its own snapshot. It cannot
		// inherit a sibling's BER form after an insertion or reorder.
		key := replayPartTag(part.tag)
		if a, b := old[key], base[key]; len(a) != 0 && len(b) != 0 && !(part.tag.Class == tag.ClassUniversal && part.tag.Number == tag.TagExternal && (current.tag.Class == tag.ClassUniversal && current.tag.Number == tag.TagSequence || current.tag.Class == tag.ClassContextSpecific && current.tag.Number == 30)) {
			plan = planReplayParts(a[0], b[0], part)
			old[key], base[key] = a[1:], b[1:]
		}
		plans = append(plans, plan)
		if plan.size < 0 {
			return replayPartPlan{size: -1}
		}
		var err error
		size, err = checkedBERCapacity(math.MaxInt, size, plan.size)
		if err != nil {
			return replayPartPlan{size: -1}
		}
	}
	return wrapReplayPart(received, plans, size)
}

func shiftReplayPart(part *replayPart, offset int) {
	part.start += offset
	for _, child := range part.children {
		shiftReplayPart(child, offset)
	}
}

func wrapReplayPart(received *replayPart, children []replayPartPlan, size int) replayPartPlan {
	header := received.header
	if !received.cleanHeader || !received.indefinite && size != len(received.content) {
		header = append(received.tag.Encode(), EncodeLength(size)...)
	}
	eoc := received.indefinite && received.cleanHeader
	tail := 0
	if eoc {
		tail = 2
	}
	total, err := checkedBERCapacity(math.MaxInt, len(header), size, tail)
	if err != nil {
		return replayPartPlan{size: -1}
	}
	return replayPartPlan{header: header, children: children, size: total, eoc: eoc}
}

func (plan replayPartPlan) appendTo(output []byte) []byte {
	output = append(output, plan.header...)
	output = append(output, plan.content...)
	for _, child := range plan.children {
		output = child.appendTo(output)
	}
	if plan.eoc {
		output = append(output, 0, 0)
	}
	return output
}

func replayUnchangedParts(encoded []byte, node *ReplayNode) []byte {
	state := node.state
	if state.profileIndex == nil || len(state.baselineBytes) == 0 {
		return encoded
	}
	baseline := state.baselineBytes
	record := state.baselineNodes[node]
	if record != nil {
		if record.start >= 0 && record.end >= record.start && record.end <= len(baseline) {
			baseline = baseline[record.start:record.end]
		} else {
			baseline = state.profileIndex.baselines[node]
			if len(baseline) == 0 {
				return encoded
			}
		}
	} else if node != state.root {
		return encoded
	}
	a, b, c := replayPartRoot(node.original), replayPartRoot(baseline), replayPartRoot(encoded)
	if a == nil || b == nil || c == nil {
		return encoded
	}
	if record != nil {
		markReplayBoundaries(b, record)
	}
	index := state.profileIndex
	position, known := index.nodes[node]
	if position.logical != nil {
		index = position.logical
	}
	offset := position.offset
	if !known && node != state.root {
		return encoded
	}
	shiftReplayPart(a, offset)
	markReplayPartBaseline(a, b)
	cursor, _ := slices.BinarySearch(index.offsets, offset)
	markReplayPartSafety(a, index, &cursor)
	plan := planReplayParts(a, b, c)
	if plan.size < 0 {
		return encoded
	}
	return plan.appendTo(make([]byte, 0, plan.size))
}

// A generated child owns its own primitive decisions. Match its canonical
// span by the collector's recorded placement, never by equal sibling bytes.
func markReplayBoundaries(part *replayPart, record *replayRecord) {
	bounds := make(map[int]int, len(record.children))
	for _, child := range record.children {
		if child.offset >= 0 {
			bounds[child.offset] = child.offset + child.length
		}
	}
	var visit func(*replayPart)
	visit = func(current *replayPart) {
		if end, ok := bounds[current.start]; ok && end == current.start+len(current.wire) {
			current.boundary = true
			return
		}
		for _, child := range current.children {
			visit(child)
		}
	}
	visit(part)
}

// External keeps its decoded snapshot in the owned runtime's private fields.
// Reflection reads those immutable bytes without changing the public API or
// allowing another sibling's snapshot to become replay authority.
func replayExternalEditedParts(value runtime.External, encoded []byte, options []EncodeOption) []byte {
	edited := false
	for _, option := range options {
		if _, disabled := option.(withoutBERReplayOption); disabled {
			return encoded
		}
		if mode, ok := option.(replayModeOption); ok {
			if mode.baseline || mode.comparison || mode.collector != nil {
				return encoded
			}
			edited = edited || mode.rebuildChildren
		}
	}
	if !edited {
		return encoded
	}
	config, err := encodeOptions(options)
	if err != nil || config.tolerant {
		return encoded
	}
	original := reflect.ValueOf(value).FieldByName("originalBER").Bytes()
	if len(original) == 0 {
		return encoded
	}
	before, n, err := DecodeExternal(original, WithoutReplayCapture(), encodingStructureOption(original))
	if err != nil || n != len(original) {
		return encoded
	}
	baseline, err := encodeExternal(before, false, replayModeOption{state: new(ReplayState), baseline: true})
	if err != nil {
		return encoded
	}
	a, b, c := replayPartRoot(original), replayPartRoot(baseline), replayPartRoot(encoded)
	if a == nil || b == nil || c == nil {
		return encoded
	}
	index := new(replayProfileIndex)
	collectReplayPartViolations(a, index, true, false)
	markReplayPartBaseline(a, b)
	cursor := 0
	markReplayPartSafety(a, index, &cursor)
	plan := planReplayParts(a, b, c)
	if plan.size < 0 {
		return encoded
	}
	return plan.appendTo(make([]byte, 0, plan.size))
}

func collectReplayPartViolations(part *replayPart, index *replayProfileIndex, owned, encodingPayload bool) {
	if owned && !part.cleanHeader {
		index.offsets = append(index.offsets, part.start)
	}
	for _, child := range part.children {
		// X.690 §8.18.6: octet-aligned and arbitrary have their underlying
		// string types even though their identifiers are IMPLICIT.
		encoding := part.tag.Class == tag.ClassUniversal && part.tag.Number == tag.TagExternal && child.tag.Class == tag.ClassContextSpecific && child.tag.Number <= 2
		if owned && encoding && child.tag.Constructed && (child.tag.Number == 1 || child.tag.Number == 2) {
			index.offsets = append(index.offsets, child.start)
		}
		// X.690 (02/2021) §§8.18.9–8.18.11: the choice header is
		// owned, while the encoded data value is foreign.
		collectReplayPartViolations(child, index, owned && !encodingPayload, encoding)
	}
}

// Compare framing and primitive contents once rather than comparing complete
// constructed byte strings again at every nesting level.
func markReplayPartBaseline(received, baseline *replayPart) bool {
	same := received.tag == baseline.tag && bytes.Equal(received.header, baseline.header) && len(received.children) == len(baseline.children)
	if !received.tag.Constructed || !baseline.tag.Constructed {
		same = same && bytes.Equal(received.content, baseline.content)
	} else {
		// Map tags once so DEFAULT/OPTIONAL presence and constructed-string repairs
		// cannot displace the correspondence of a later field.
		byTag := make(map[tag.Tag][]*replayPart, len(baseline.children))
		for _, child := range baseline.children {
			byTag[child.tag] = append(byTag[child.tag], child)
		}
		for _, child := range received.children {
			matches := byTag[child.tag]
			if len(matches) == 0 {
				same = false
				continue
			}
			same = markReplayPartBaseline(child, matches[0]) && same
			byTag[child.tag] = matches[1:]
		}
	}
	received.baselineSame = same
	return same
}

// BER string construction is representation, not a different component tag.
// X.690 (02/2021) §§8.7, 8.23.3. The baseline still supplies the typed value
// comparison, and the received span must pass the protocol profile.
func replayPartTag(identifier tag.Tag) tag.Tag {
	identifier.Constructed = false
	return identifier
}
