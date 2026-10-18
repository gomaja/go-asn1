// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

// Runtime source: runtime/ber/replay_context.go; SHA-256 62005f1d8712dfdf2c8ab851b736d8709eaf6126b346e10989da8a30e85b034b.
package ber

import (
	"bytes"
	"fmt"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
	"math"
	"math/big"
	"reflect"
	"strings"
	"sync"
)

// ReplayState owns a decoded value's first replay decision. Both modes retain
// a detached typed baseline. Proof mode encodes its comparison stream on
// demand; light mode records that stream at decode completion.
// X.690 (02/2021) §§8.1.3 and 8.7.3 permit distinct BER encodings of the
// same value, including indefinite lengths and nonminimal definite lengths.
type ReplayState struct {
	once           sync.Once
	root           *ReplayNode
	baseline       func(EncodeOption) ([]byte, error)
	same           func(any, *replayNodeComparisons) berValueComparison
	baselineBytes  []byte
	baselineNodes  map[*ReplayNode]*replayRecord
	eagerBaseline  bool
	decodeTolerant bool
	nodeCount      int
	disabled       bool
	sink           ViolationLog
}

// ReplayNode identifies one generated value in both the decoded tree and its
// decode-time copy. Its baseline range points into one comparison byte stream.
// A parent compares its wrapper around replayed children bottom-up.
type ReplayNode struct {
	state        *ReplayState
	original     []byte
	wireTag      tag.Tag
	wireTagKnown bool
}

func (s *ReplayState) setBaseline(encode func(EncodeOption) ([]byte, error)) {
	s.baseline = encode
}

type replayModeOption struct {
	state      *ReplayState
	baseline   bool
	strict     bool
	diagnostic bool
	comparison bool
	shortcut   bool
	collector  *replayCollector
	sink       *ViolationLog
	fast       *replayFastState
	unchanged  map[*ReplayNode]bool
	typed      *replayNodeComparisons
	top        *ReplayNode
	prepared   []byte
}

// replayFastState lets a changed value reuse received child octets during its
// first encode. If a node cannot be proved unchanged from its own received
// range, the caller falls back to the canonical stream comparison.
type replayFastState struct {
	state       *ReplayState
	root        *ReplayNode
	rootDirty   bool // the decoded and current values are provably different
	rootUnknown bool // value comparison cannot decide
	nodeValues  *replayNodeComparisons
	stack       []replayFastFrame
	matched     map[*ReplayNode]bool
	uncertain   bool
}

type replayFastFrame struct {
	node           *ReplayNode
	childChanged   bool
	childReplayed  bool
	replayedNode   *ReplayNode
	replayedBytes  []byte
	replayedCount  int
	replayedOffset int
	replayedLength int
	placementSeen  bool
}

func (s *replayFastState) enter(node *ReplayNode) {
	if node.original != nil {
		s.stack = append(s.stack, replayFastFrame{node: node})
	}
}

func (s *replayFastState) leave(node *ReplayNode, encoded []byte) []byte {
	if len(s.stack) == 0 || s.stack[len(s.stack)-1].node != node {
		s.uncertain = true
		return encoded
	}
	frame := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	result := encoded
	changed := frame.childChanged
	// Received contents alone cannot prove that the decoded value survived
	// an edit: BER BIT STRING unused bits can make a new encoding look
	// received (X.690 (02/2021) §8.6.2.2; DER tightens this in §11.2.1).
	if comparison, _ := s.nodeValues.get(reflect.ValueOf(node).Pointer()); comparison == berValueDifferent {
		// A changed node is established by its typed ASN.1 value, not by
		// comparing received BER with a canonical stream.
		changed = true
	} else if replayNodeMatchesReceived(node, encoded, s.state) && replayNodeMatchesBaseline(node, encoded, s.state) {
		result = node.original
		changed = false
	} else if !changed {
		if node == s.root && s.rootUnknown {
			s.uncertain = true
		} else if node == s.root && s.rootDirty {
			changed = true
		} else if frame.childReplayed {
			if same, known := replaySequenceWithOneReplayedChild(node, encoded, frame, s.state); same && known {
				result = node.original
			} else {
				s.uncertain = true
			}
		} else {
			// A baseline disagreement compares encoded octets that may still
			// carry received child forms. It does not prove a value change
			// (X.690 (02/2021) §§8.1.3, 8.14).
			s.uncertain = true
		}
	}
	if len(s.stack) != 0 {
		parent := &s.stack[len(s.stack)-1]
		parent.childChanged = parent.childChanged || changed
		if !bytes.Equal(result, encoded) {
			parent.childReplayed = true
			parent.replayedNode = node
			parent.replayedBytes = result
			parent.replayedCount++
		}
	}
	if s.matched != nil && bytes.Equal(result, node.original) {
		s.matched[node] = true
	}
	return result
}

// A SEQUENCE preserves child order. With one replayed generated child,
// matching octets around that child prove a match. A mismatch is uncertain:
// another sibling can carry a received BER form (X.690 (02/2021) §§8.1.3,
// 8.14), so byte differences do not prove a value change.
func replaySequenceWithOneReplayedChild(node *ReplayNode, encoded []byte, frame replayFastFrame, state *ReplayState) (same, known bool) {
	if frame.replayedCount != 1 {
		return false, false
	}
	before := state.baselineNodes[node]
	child := state.baselineNodes[frame.replayedNode]
	if before == nil || child == nil || !before.tagKnown || before.canonicalTag != (tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence, Constructed: true}) ||
		before.start < 0 || before.end > len(state.baselineBytes) || child.start < before.start || child.end > before.end {
		return false, false
	}
	direct := false
	for _, candidate := range before.children {
		if candidate == child {
			direct = true
			break
		}
	}
	if !direct {
		return false, false
	}
	baseWire := state.baselineBytes[before.start:before.end]
	_, baseContent, baseOK := replayContentView(baseWire)
	_, currentContent, currentOK := replayContentView(encoded)
	if !baseOK || !currentOK {
		return false, false
	}
	baseContentStart, ok := berSubsliceOffset(baseWire, baseContent)
	if !ok {
		return false, false
	}
	baseChildStart := child.start - before.start - baseContentStart
	baseChildEnd := child.end - before.start - baseContentStart
	if baseChildStart < 0 || baseChildEnd > len(baseContent) || baseChildStart > baseChildEnd {
		return false, false
	}
	currentChildStart, currentChildLength := frame.replayedOffset, frame.replayedLength
	if currentChildStart < 0 || currentChildStart > len(currentContent) || currentChildLength < 0 || currentChildLength > len(currentContent)-currentChildStart ||
		!frame.placementSeen {
		return false, false
	}
	if bytes.Equal(currentContent[:currentChildStart], baseContent[:baseChildStart]) &&
		bytes.Equal(currentContent[currentChildStart+currentChildLength:], baseContent[baseChildEnd:]) {
		return true, true
	}
	return false, false
}

// A record keeps only a range in the root stream. pending refers to a child
// encoder's result until its parent has located it, then is released.
type replayRecord struct {
	node         *ReplayNode
	children     []*replayRecord
	pending      []byte
	contents     []byte
	placed       bool
	nextChild    int
	offset       int
	length       int
	start        int
	end          int
	canonicalTag tag.Tag
	tagKnown     bool
}

type replayCollector struct {
	stack []*replayRecord
	root  *replayRecord
	nodes map[*ReplayNode]*replayRecord
	order []*replayRecord
	sink  ViolationLog
	err   error
}

func newReplayCollector(wireLength int) *replayCollector {
	capacity := max(1, min(wireLength/2, 256))
	return &replayCollector{
		stack: make([]*replayRecord, 0, capacity),
		nodes: make(map[*ReplayNode]*replayRecord, capacity),
		order: make([]*replayRecord, 0, capacity),
	}
}

func (c *replayCollector) enter(node *ReplayNode) {
	if c.nodes == nil {
		c.nodes = make(map[*ReplayNode]*replayRecord)
	}
	if _, exists := c.nodes[node]; exists {
		c.err = fmt.Errorf("%w: BER replay node appears more than once", ErrInvalidValue)
	}
	record := &replayRecord{node: node, start: -1, end: -1, offset: -1}
	c.nodes[node] = record
	c.stack = append(c.stack, record)
}

func (c *replayCollector) leave(node *ReplayNode, encoded []byte) {
	if len(c.stack) == 0 || c.stack[len(c.stack)-1].node != node {
		c.err = fmt.Errorf("%w: BER replay nodes are not nested", ErrInvalidValue)
		return
	}
	record := c.stack[len(c.stack)-1]
	c.stack = c.stack[:len(c.stack)-1]
	record.pending = encoded
	record.length = len(encoded)
	if t, _, err := DecodeTag(encoded); err == nil {
		record.canonicalTag, record.tagKnown = t, true
	}
	if record.contents != nil {
		if start, ok := replayContainerOffset(encoded, record.contents); ok {
			for _, child := range record.children {
				if child.offset >= 0 {
					child.offset += start
				}
			}
		} else {
			for _, child := range record.children {
				child.offset = -1
			}
		}
	} else if len(record.children) == 1 && !record.children[0].placed {
		// A CHOICE forwards exactly one generated alternative. Its wrapper
		// contains that alternative at the beginning, never at a later equal
		// element.
		child := record.children[0]
		child.offset, child.length = replayChildAtPosition(encoded, child.pending)
	}
	for _, child := range record.children {
		child.pending = nil
	}
	record.contents = nil
	if len(c.stack) == 0 {
		c.root = record
	} else {
		c.stack[len(c.stack)-1].children = append(c.stack[len(c.stack)-1].children, record)
	}
	c.order = append(c.order, record)
}

// RecordGeneratedBERChildPlacement associates the most recently encoded
// generated child with the component the parent is about to append. Its
// position comes from the encoder, never from an equal-octet search. X.690
// (02/2021) §8.14.4 permits an IMPLICIT tag to replace the identifier.
func RecordGeneratedBERChildPlacement(options []EncodeOption, offset int, component []byte) {
	for _, option := range options {
		mode, ok := option.(replayModeOption)
		if !ok {
			continue
		}
		if mode.fast != nil && len(mode.fast.stack) != 0 {
			frame := &mode.fast.stack[len(mode.fast.stack)-1]
			if frame.childReplayed && !frame.placementSeen {
				frame.placementSeen = true
				position, length := replayChildAtPosition(component, frame.replayedBytes)
				if position >= 0 {
					frame.replayedOffset, frame.replayedLength = offset+position, length
				} else {
					frame.replayedOffset = -1
				}
			}
			return
		}
		if mode.collector == nil || len(mode.collector.stack) == 0 {
			return
		}
		parent := mode.collector.stack[len(mode.collector.stack)-1]
		if parent.nextChild < len(parent.children) {
			child := parent.children[parent.nextChild]
			parent.nextChild++
			child.placed = true
			position, length := replayChildAtPosition(component, child.pending)
			if position >= 0 {
				child.offset, child.length = offset+position, length
			}
		}
		return
	}
}

// RecordGeneratedBERContainer records the bytes assembled by a generated
// SEQUENCE, SET or collection before its outer tag and length are encoded.
func RecordGeneratedBERContainer(options []EncodeOption, contents []byte) {
	for _, option := range options {
		mode, ok := option.(replayModeOption)
		if ok && mode.collector != nil && len(mode.collector.stack) != 0 {
			mode.collector.stack[len(mode.collector.stack)-1].contents = contents
			return
		}
	}
}

func replayChildAtPosition(component, child []byte) (int, int) {
	_, childContent, ok := replayContentView(child)
	if !ok {
		return -1, 0
	}
	position := 0
	for len(component) != 0 {
		t, content, valid := replayContentView(component)
		if !valid {
			return -1, 0
		}
		if sameBERSlice(component, child) || bytes.Equal(component, child) || bytes.Equal(content, childContent) {
			return position, len(component)
		}
		if !t.Constructed || len(content) == 0 {
			return -1, 0
		}
		contentOffset, ok := berSubsliceOffset(component, content)
		if !ok {
			return -1, 0
		}
		position += contentOffset
		component = content
	}
	return -1, 0
}

func replayContainerOffset(encoded, children []byte) (int, bool) {
	position := 0
	for len(encoded) != 0 {
		t, content, ok := replayContentView(encoded)
		if !ok || !t.Constructed {
			return 0, false
		}
		start, ok := berSubsliceOffset(encoded, content)
		if !ok {
			return 0, false
		}
		position += start
		if len(content) == len(children) {
			// The generated BER encoder passes children directly to
			// EncodeSequence, EncodeSet or EncodeConstructed. Each copies
			// those octets in order; an outer EXPLICIT tag can only add a
			// complete wrapper (X.690 (02/2021) §§8.10–8.14).
			return position, true
		}
		if len(content) < len(children) {
			return 0, false
		}
		encoded = content
	}
	return 0, false
}

// replayContentView inspects a full, already validated or encoder-produced
// element without rescanning nested indefinite contents. X.690 (02/2021)
// §§8.1.3.6 and 8.1.5 define the final end-of-contents pair.
func replayContentView(data []byte) (tag.Tag, []byte, bool) {
	t, tagLength, err := DecodeTag(data)
	if err != nil || tagLength > len(data) {
		return tag.Tag{}, nil, false
	}
	length, indefinite, lengthLength, err := DecodeLength(data[tagLength:])
	if err != nil || lengthLength > len(data)-tagLength {
		return tag.Tag{}, nil, false
	}
	start := tagLength + lengthLength
	if indefinite {
		if !t.Constructed || len(data)-start < 2 || data[len(data)-2] != 0 || data[len(data)-1] != 0 {
			return tag.Tag{}, nil, false
		}
		return t, data[start : len(data)-2], true
	}
	if length != len(data)-start {
		return tag.Tag{}, nil, false
	}
	return t, data[start:], true
}

// finish maps each generated child into the one root encoding.
func (c *replayCollector) finish(encoded []byte) error {
	if c.err != nil {
		return c.err
	}
	if len(c.stack) != 0 || c.root == nil || !bytes.Equal(c.root.pending, encoded) {
		return fmt.Errorf("%w: incomplete BER replay comparison stream", ErrInvalidValue)
	}
	c.root.start = 0
	c.root.end = len(encoded)
	for index := len(c.order) - 1; index >= 0; index-- {
		parent := c.order[index]
		for _, child := range parent.children {
			if parent.start < 0 || child.offset < 0 {
				continue
			}
			parentLength := parent.end - parent.start
			if child.offset < 0 || child.length < 0 || child.offset > parentLength || child.length > parentLength-child.offset {
				return fmt.Errorf("%w: BER replay child range exceeds parent", ErrInvalidValue)
			}
			child.start = parent.start + child.offset
			child.end = child.start + child.length
		}
	}
	c.root.pending = nil
	return nil
}

func replayNodeMatchesBaseline(node *ReplayNode, encoded []byte, state *ReplayState) bool {
	before := state.baselineNodes[node]
	if before == nil || before.start < 0 || before.end < before.start || before.end > len(state.baselineBytes) {
		return false
	}
	prior := state.baselineBytes[before.start:before.end]
	if bytes.Equal(encoded, prior) {
		return true
	}
	// X.690 (02/2021) §§8.1.3 and 8.14: length forms and an IMPLICIT
	// parent tag can differ from this node's canonical header. A node is
	// compared only with its own recorded range, never with a sibling whose
	// content happens to be equal.
	if !before.tagKnown {
		return false
	}
	currentTag, currentContent, currentOK := replayContentView(encoded)
	if !currentOK || currentTag != before.canonicalTag {
		return false
	}
	_, priorContent, priorOK := replayContentView(prior)
	return priorOK && bytes.Equal(currentContent, priorContent)
}

func replayNodeMatchesReceived(node *ReplayNode, encoded []byte, state *ReplayState) bool {
	if bytes.Equal(encoded, node.original) {
		return true
	}
	before := state.baselineNodes[node]
	if before == nil || !before.tagKnown {
		return false
	}
	currentTag, currentContent, currentOK := replayContentView(encoded)
	if !currentOK || currentTag != before.canonicalTag {
		return false
	}
	_, receivedContent, receivedOK := replayContentView(node.original)
	return receivedOK && bytes.Equal(currentContent, receivedContent)
}

func (option replayModeOption) applyEncode(config *encodeConfig) error {
	if option.state == nil {
		return fmt.Errorf("%w: invalid BER replay state", ErrInvalidValue)
	}
	if option.baseline || option.comparison && !option.strict || option.collector != nil && !option.strict {
		config.tolerant = true
		if option.sink != nil {
			config.violations = option.sink
		} else if option.collector != nil && !option.baseline {
			config.violations = &option.collector.sink
		} else {
			config.violations = &option.state.sink
		}
	}
	return nil
}

// PrepareBERReplay initializes the decode-time baseline on the first encode.
// Generated child encoders inherit its option and never repeat the baseline.
func PrepareBERReplay(node *ReplayNode, options []EncodeOption, canonical func(EncodeOption) ([]byte, error), current any) ([]EncodeOption, error) {
	if node == nil || node.state == nil {
		return options, nil
	}
	hasMode := false
	noReplay := false
	for _, option := range options {
		switch value := option.(type) {
		case replayModeOption:
			if value.state == node.state {
				hasMode = true
				if value.collector != nil && !value.comparison {
					value.collector.enter(node)
				}
				if value.fast != nil {
					value.fast.enter(node)
				}
			}
		case withoutBERReplayOption:
			noReplay = true
		}
	}
	if hasMode || noReplay {
		return options, nil
	}
	state := node.state
	if state.disabled {
		return options, nil
	}
	// A strict decode already checked the retained value. Equality with its
	// detached baseline proves that no canonical comparison is needed.
	rootDirty, rootUnknown := false, false
	config, optionErr := encodeOptions(options)
	if optionErr != nil {
		return nil, optionErr
	}
	strict := !config.tolerant
	// Tolerant decoding does not prove current value or text rules. Before
	// any typed replay shortcut, walk the current tree with strict checks and
	// diagnostic paths. Q.773 (06/1997) §§4.2.2.2, 4.2.3; X.680 §51.
	if strict && state.decodeTolerant && canonical != nil {
		if _, err := canonical(replayModeOption{state: state, comparison: true, strict: true, diagnostic: true}); err != nil {
			return nil, err
		}
	}
	rootComparison := berValueUnknown
	var nodeValues *replayNodeComparisons
	if strict && state.same != nil && node == state.root {
		if state.nodeCount > 1 {
			nodeValues = new(replayNodeComparisons)
		}
		rootComparison = state.same(current, nodeValues)
		switch rootComparison {
		case berValueEqual:
			if !state.decodeTolerant {
				return []EncodeOption{replayModeOption{state: state, top: node, shortcut: true}}, nil
			}
		case berValueDifferent:
			rootDirty = true
		default:
			rootUnknown = true
		}
	}
	if strict && rootComparison == berValueDifferent && !state.eagerBaseline {
		// Every decoded node with a firm typed verdict can make its replay
		// decision from that value comparison. A changed root with no child
		// needs no baseline either. Equal children retain their received
		// octets (X.690 (02/2021) §§8.1.3, 8.9.2).
		if state.nodeCount == 1 {
			return []EncodeOption{replayModeOption{state: state, top: node}}, nil
		}
		if nodeValues.complete(state.nodeCount) {
			return []EncodeOption{replayModeOption{state: state, top: node, typed: nodeValues}}, nil
		}
	}
	if !state.eagerBaseline {
		state.once.Do(func() {
			if state.baseline == nil {
				state.disabled = true
				return
			}
			collector := newReplayCollector(len(node.original))
			baseline, err := state.baseline(replayModeOption{state: state, baseline: true, collector: collector})
			if err != nil || collector.finish(baseline) != nil {
				state.disabled = true
			} else {
				state.baselineBytes = baseline
				state.baselineNodes = collector.nodes
			}
			state.baseline = nil
		})
	}
	if state.disabled {
		return options, nil
	}
	if canonical == nil {
		return nil, fmt.Errorf("%w: BER replay comparison encoder is unavailable", ErrInvalidValue)
	}
	if rootComparison != berValueUnknown && strict {
		// A firm typed result supplies the replay decision for every known
		// generated node. The generated encoder can then make its final pass
		// directly, preserving equal descendants without a comparison pass.
		// An equal root has no edited sibling that could displace a received
		// nested length; strict validation still runs in the final encode.
		if rootComparison == berValueDifferent && len(state.baselineNodes) == 1 {
			return []EncodeOption{replayModeOption{state: state, top: node}}, nil
		}
		complete := true
		for candidate := range state.baselineNodes {
			comparison, ok := nodeValues.get(reflect.ValueOf(candidate).Pointer())
			if !ok || comparison == berValueUnknown {
				complete = false
				break
			}
		}
		if complete {
			return []EncodeOption{replayModeOption{state: state, top: node, typed: nodeValues}}, nil
		}
	}
	var fastBytes []byte
	var fastMatches map[*ReplayNode]bool
	if strict {
		fast := &replayFastState{state: state, root: node, rootDirty: rootDirty, rootUnknown: rootUnknown, nodeValues: nodeValues, stack: make([]replayFastFrame, 0, min(len(state.baselineNodes), 16)), matched: make(map[*ReplayNode]bool, len(state.baselineNodes))}
		prepared, err := canonical(replayModeOption{state: state, strict: true, fast: fast})
		if err == nil && !fast.uncertain && len(fast.stack) == 0 {
			return []EncodeOption{replayModeOption{state: state, top: node, prepared: prepared, shortcut: bytes.Equal(prepared, node.original)}}, nil
		}
		if err == nil && len(fast.stack) == 0 {
			fastBytes, fastMatches = prepared, fast.matched
		}
	}
	unchanged := make(map[*ReplayNode]bool, len(state.baselineNodes))
	var sink ViolationLog
	_, err := canonical(replayModeOption{state: state, comparison: true, strict: strict, unchanged: unchanged, sink: &sink})
	if err != nil {
		if strict {
			_, diagnosticErr := canonical(replayModeOption{state: state, comparison: true, strict: true, diagnostic: true, unchanged: make(map[*ReplayNode]bool)})
			if diagnosticErr != nil {
				return nil, diagnosticErr
			}
		}
		return nil, err
	}
	mode := replayModeOption{state: state, top: node, unchanged: unchanged}
	mode.shortcut = strict && mode.unchanged[node]
	if fastBytes != nil && (nodeValues != nil || state.eagerBaseline) {
		matched := true
		for replayed := range unchanged {
			if !fastMatches[replayed] {
				matched = false
				break
			}
		}
		if matched {
			mode.prepared = fastBytes
		}
	}
	return append(options[:len(options):len(options)], mode), nil
}

func generatedEncodePublicOptionCount(options []EncodeOption) int {
	if len(options) == 1 {
		if _, generated := options[0].(generatedEncodeMarker); generated {
			return 0
		}
		return 1
	}
	count := 0
	for _, option := range options {
		if _, generated := option.(generatedEncodeMarker); !generated {
			count++
		}
	}
	return count
}

// PreparedBERReplay returns the root's received bytes when its strict value
// is unchanged, or the prepared canonical bytes when no node can replay.
// The caller receives a separate copy in either case.
func PreparedBERReplay(node *ReplayNode, options []EncodeOption) ([]byte, bool) {
	if node == nil || node.original == nil || len(options) == 0 {
		return nil, false
	}
	var mode replayModeOption
	found := false
	if len(options) == 1 {
		mode, found = options[0].(replayModeOption)
	} else if generatedEncodePublicOptionCount(options) == 1 {
		for _, option := range options {
			if candidate, ok := option.(replayModeOption); ok {
				mode, found = candidate, true
			}
		}
	}
	if !found || mode.top != node || mode.state != node.state {
		return nil, false
	}
	if mode.prepared != nil {
		return bytes.Clone(mode.prepared), true
	}
	if !mode.shortcut {
		return nil, false
	}
	return bytes.Clone(node.original), true
}

// PreserveEncodedBERNode replays a node's received octets when its current
// encoding matches the encoding of its decode-time value. The baseline pass
// records the comparison once; it never re-encodes a descendant recursively.
func PreserveEncodedBERNode(encoded []byte, node *ReplayNode, options []EncodeOption) []byte {
	if node == nil || node.original == nil {
		return encoded
	}
	var mode replayModeOption
	hasMode := false
	for _, option := range options {
		if _, disabled := option.(withoutBERReplayOption); disabled {
			return encoded
		}
		if candidate, ok := option.(replayModeOption); ok && candidate.state == node.state {
			mode, hasMode = candidate, true
		}
	}
	if hasMode {
		if mode.shortcut && mode.top == node {
			return bytes.Clone(node.original)
		}
		if mode.fast != nil {
			return mode.fast.leave(node, encoded)
		}
		if mode.comparison {
			if mode.unchanged != nil && replayNodeMatchesBaseline(node, encoded, mode.state) {
				mode.unchanged[node] = true
			}
			return encoded
		}
		if mode.collector != nil {
			mode.collector.leave(node, encoded)
			return encoded
		}
		if mode.typed != nil {
			if comparison, _ := mode.typed.get(reflect.ValueOf(node).Pointer()); comparison == berValueEqual {
				if mode.top == node {
					return bytes.Clone(node.original)
				}
				return node.original
			}
			return encoded
		}
		if mode.unchanged[node] {
			if mode.top == node {
				return bytes.Clone(node.original)
			}
			return node.original
		}
	}
	return encoded
}

// CloneBERValue copies the mutable fields of a decoded value without BER
// encoding. Replay nodes and their immutable received octets remain shared.
func CloneBERValue(value any) (any, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: nil BER replay value", ErrInvalidValue)
	}
	clone, err := cloneBERReflect(reflect.ValueOf(value), make(map[reflect.Value]reflect.Value))
	if err != nil {
		return nil, err
	}
	return clone.Interface(), nil
}

// compareBERValue compares a decoded value with its detached baseline. A
// definite value difference can skip comparison encoding; an unprovable
// comparison must fall back to the byte-stream comparison. The common acyclic
// generated tree needs no visited-pointer map.
type berValueComparison uint8

const (
	berValueUnknown berValueComparison = iota
	berValueEqual
	berValueDifferent
)

type berComparisonField struct {
	index          int
	optional       bool
	extData        bool
	valueField     bool
	replayNode     bool
	containsReplay bool
	nilable        bool
	quickKind      reflect.Kind
	byteSlice      bool
}

type berComparisonPlan struct {
	fields          []berComparisonField
	alternatives    []int
	choiceExtension int
	choice          bool
	external        bool
	replayFields    []int
}

var berComparisonPlans sync.Map

func berPlanFor(typ reflect.Type) *berComparisonPlan {
	if cached, ok := berComparisonPlans.Load(typ); ok {
		return cached.(*berComparisonPlan)
	}
	plan := &berComparisonPlan{fields: make([]berComparisonField, typ.NumField()), choiceExtension: -1, external: typ.ConvertibleTo(externalType)}
	if typ.NumField() > 1 {
		first := typ.Field(0)
		if first.Name == "Choice" && first.Type.Kind() == reflect.Int {
			_, tagged := first.Tag.Lookup("asn1")
			plan.choice = !tagged
		}
	}
	hasReplayNode := false
	for index := range plan.fields {
		field := typ.Field(index)
		tagValue := field.Tag.Get("asn1")
		replayNode := field.Type == replayNodeType
		kind := field.Type.Kind()
		entry := berComparisonField{
			index:          index,
			optional:       field.PkgPath == "" && strings.Contains(","+tagValue+",", ",optional,"),
			extData:        field.PkgPath == "" && tagValue == "-" && field.Name == "ExtData_" && field.Type == reflect.TypeFor[[][]byte](),
			valueField:     field.PkgPath == "" && tagValue != "-",
			replayNode:     replayNode,
			containsReplay: berTypeContainsReplay(field.Type, make(map[reflect.Type]bool)),
			nilable:        kind == reflect.Pointer || kind == reflect.Slice || kind == reflect.Map || kind == reflect.Interface || kind == reflect.Func,
			quickKind:      kind,
			byteSlice:      kind == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8,
		}
		plan.fields[index] = entry
		if replayNode {
			hasReplayNode = true
			plan.replayFields = append(plan.replayFields, index)
		} else if plan.choice && field.Type == reflect.TypeFor[*runtime.BERChoiceExtension]() {
			// X.680 (02/2021) §§29.1, 52.1: the extension holder is
			// outside the numbered known alternatives.
			plan.choiceExtension = index
		} else if plan.choice && index > 0 && field.PkgPath == "" {
			plan.alternatives = append(plan.alternatives, index)
		}
	}
	plan.choice = plan.choice && hasReplayNode
	actual, _ := berComparisonPlans.LoadOrStore(typ, plan)
	return actual.(*berComparisonPlan)
}

func berTypeContainsReplay(typ reflect.Type, seen map[reflect.Type]bool) bool {
	if typ == replayNodeType {
		return true
	}
	if typ == realType || typ == bigIntType || typ == bitStringType || typ == rawValueType ||
		typ == objectIdentifierType || typ == relativeObjectIdentifierType || typ.ConvertibleTo(externalType) {
		return false
	}
	if seen[typ] {
		return true // A recursive type may contain a replay node at a greater depth.
	}
	seen[typ] = true
	defer delete(seen, typ)
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return berTypeContainsReplay(typ.Elem(), seen)
	case reflect.Interface:
		return true // The dynamic value may contain a replay node.
	case reflect.Struct:
		for index := 0; index < typ.NumField(); index++ {
			if berTypeContainsReplay(typ.Field(index).Type, seen) {
				return true
			}
		}
	}
	return false
}

// Most generated BER trees have at most eight replay nodes. Keeping their
// comparisons inline avoids a heap map on every edited encode.
type replayNodeComparisons struct {
	count         int
	inlineNodes   [8]uintptr
	inlineResults [8]berValueComparison
	overflow      map[uintptr]berValueComparison
}

func (c *replayNodeComparisons) put(node uintptr, result berValueComparison) {
	if c == nil {
		return
	}
	for index := 0; index < c.count; index++ {
		if c.inlineNodes[index] == node {
			c.inlineResults[index] = result
			return
		}
	}
	if c.count < len(c.inlineNodes) {
		c.inlineNodes[c.count] = node
		c.inlineResults[c.count] = result
		c.count++
		return
	}
	if c.overflow == nil {
		c.overflow = make(map[uintptr]berValueComparison)
	}
	c.overflow[node] = result
}

func (c *replayNodeComparisons) get(node uintptr) (berValueComparison, bool) {
	if c == nil {
		return berValueUnknown, false
	}
	for index := 0; index < c.count; index++ {
		if c.inlineNodes[index] == node {
			return c.inlineResults[index], true
		}
	}
	result, ok := c.overflow[node]
	return result, ok
}

func (c *replayNodeComparisons) complete(count int) bool {
	if c == nil || c.count+len(c.overflow) != count {
		return false
	}
	for index := 0; index < c.count; index++ {
		if c.inlineResults[index] == berValueUnknown {
			return false
		}
	}
	for _, result := range c.overflow {
		if result == berValueUnknown {
			return false
		}
	}
	return true
}

func berComparison(equal bool) berValueComparison {
	if equal {
		return berValueEqual
	}
	return berValueDifferent
}

func compareBERValueNodes(left, right reflect.Value, depth int, nodeValues *replayNodeComparisons) berValueComparison {
	if !left.IsValid() || !right.IsValid() {
		return berComparison(left.IsValid() == right.IsValid())
	}
	typ := left.Type()
	if typ != right.Type() || depth > 1024 {
		return berValueUnknown
	}
	var plan *berComparisonPlan
	if typ.Kind() == reflect.Struct {
		plan = berPlanFor(typ)
		if plan.external && left.CanAddr() && right.CanAddr() &&
			left.Addr().CanInterface() && right.Addr().CanInterface() &&
			left.Addr().CanConvert(externalPointerType) && right.Addr().CanConvert(externalPointerType) {
			// X.690 (02/2021) §8.18.1: the encoding CHOICE contributes only
			// its selected alternative to the EXTERNAL value.
			a := left.Addr().Convert(externalPointerType).Interface().(*runtime.External)
			b := right.Addr().Convert(externalPointerType).Interface().(*runtime.External)
			if a.Encoding != b.Encoding || a.DirectReference != b.DirectReference {
				return berValueDifferent
			}
			if (a.IndirectReference == nil) != (b.IndirectReference == nil) ||
				(a.DataValueDescriptor == nil) != (b.DataValueDescriptor == nil) {
				return berValueUnknown
			}
			if a.IndirectReference != nil && a.IndirectReference.Cmp(b.IndirectReference) != 0 {
				return berValueDifferent
			}
			if a.DataValueDescriptor != nil && *a.DataValueDescriptor != *b.DataValueDescriptor {
				return berValueDifferent
			}
			switch a.Encoding {
			case runtime.ExternalSingleASN1Type:
				if a.SingleASN1Type.Class == b.SingleASN1Type.Class &&
					a.SingleASN1Type.Tag == b.SingleASN1Type.Tag &&
					a.SingleASN1Type.Constructed == b.SingleASN1Type.Constructed &&
					bytes.Equal(a.SingleASN1Type.Bytes, b.SingleASN1Type.Bytes) {
					return berValueEqual
				}
				return berValueUnknown
			case runtime.ExternalOctetAligned:
				return berComparison(bytes.Equal(a.OctetAligned, b.OctetAligned))
			case runtime.ExternalArbitrary:
				return compareBERValueNodes(reflect.ValueOf(&a.Arbitrary).Elem(), reflect.ValueOf(&b.Arbitrary).Elem(), depth+1, nodeValues)
			default:
				return berValueUnknown
			}
		}
		if typ == realType {
			if !left.CanInterface() || !right.CanInterface() {
				return berValueUnknown
			}
			a, b := left.Interface().(runtime.Real), right.Interface().(runtime.Real)
			if a.Validate() != nil || b.Validate() != nil {
				return berValueUnknown
			}
			// The base of a nonzero REAL is part of its abstract value:
			// X.690 (02/2021) §8.5.4 distinguishes base 2 from base 10.
			if a.Kind == runtime.RealFinite && a.Mantissa != nil && a.Base != b.Base {
				return berValueDifferent
			}
			// X.690 (02/2021) §§8.5.4–8.5.7 permit several binary
			// mantissa and exponent representations of one REAL value.
			comparison, err := compareReal(a, b)
			if err != nil {
				return berValueUnknown
			}
			return berComparison(comparison == 0)
		}
		if typ == bigIntType {
			if !left.CanAddr() || !right.CanAddr() || !left.Addr().CanInterface() || !right.Addr().CanInterface() {
				return berValueUnknown
			}
			a, b := left.Addr().Interface().(*big.Int), right.Addr().Interface().(*big.Int)
			return berComparison(a.Cmp(b) == 0)
		}
		if typ == bitStringType {
			if !left.CanInterface() || !right.CanInterface() {
				return berValueUnknown
			}
			a, b := left.Interface().(runtime.BitString), right.Interface().(runtime.BitString)
			if !berBitStringLengthFits(a) || !berBitStringLengthFits(b) || a.BitLength != b.BitLength {
				return berValueUnknown
			}
			// X.690 (02/2021) §8.6.2.2: a difference in unused bits
			// is representational, so let the stream comparison decide
			// whether the caller explicitly changed the received form.
			full := a.BitLength / 8
			if !bytes.Equal(a.Bytes[:full], b.Bytes[:full]) {
				return berValueDifferent
			}
			if rem := a.BitLength % 8; rem != 0 {
				mask := ^byte(0) << (8 - rem)
				if a.Bytes[full]&mask != b.Bytes[full]&mask {
					return berValueDifferent
				}
			}
			if bytes.Equal(a.Bytes, b.Bytes) {
				return berValueEqual
			}
			return berValueUnknown
		}
		if typ == rawValueType {
			if !left.CanInterface() || !right.CanInterface() {
				return berValueUnknown
			}
			a, b := left.Interface().(runtime.RawValue), right.Interface().(runtime.RawValue)
			if a.Class == b.Class && a.Tag == b.Tag && a.Constructed == b.Constructed && bytes.Equal(a.Bytes, b.Bytes) {
				return berValueEqual
			}
			// An IMPLICIT site replaces identifier octets but keeps the length
			// and content (X.690 (02/2021) §8.14). A changed identifier alone
			// cannot prove that the encoded value changed; a different suffix
			// or primitive/constructed form can (X.690 (02/2021) §8.1.2).
			aTag, aLength, aErr := DecodeTag(a.Bytes)
			bTag, bLength, bErr := DecodeTag(b.Bytes)
			if aErr == nil && bErr == nil &&
				(aTag.Constructed != bTag.Constructed || !bytes.Equal(a.Bytes[aLength:], b.Bytes[bLength:])) {
				return berValueDifferent
			}
			return berValueUnknown
		}
		if typ == objectIdentifierType {
			if !left.CanInterface() || !right.CanInterface() {
				return berValueUnknown
			}
			return berComparison(left.Interface().(runtime.ObjectIdentifier) == right.Interface().(runtime.ObjectIdentifier))
		}
		if typ == relativeObjectIdentifierType {
			if !left.CanInterface() || !right.CanInterface() {
				return berValueUnknown
			}
			return berComparison(left.Interface().(runtime.RelativeObjectIdentifier) == right.Interface().(runtime.RelativeObjectIdentifier))
		}
	}
	switch typ.Kind() {
	case reflect.Bool:
		return berComparison(left.Bool() == right.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return berComparison(left.Int() == right.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return berComparison(left.Uint() == right.Uint())
	case reflect.Float32, reflect.Float64:
		// X.690 (02/2021) §8.5.9 gives NOT-A-NUMBER one abstract
		// value and distinguishes minus zero from plus zero.
		a, b := left.Float(), right.Float()
		if math.IsNaN(a) || math.IsNaN(b) {
			return berComparison(math.IsNaN(a) && math.IsNaN(b))
		}
		if a == 0 && b == 0 {
			return berComparison(math.Signbit(a) == math.Signbit(b))
		}
		return berComparison(a == b)
	case reflect.Complex64, reflect.Complex128:
		return berValueUnknown
	case reflect.String:
		return berComparison(left.String() == right.String())
	case reflect.Pointer:
		if left.IsNil() || right.IsNil() {
			if left.IsNil() == right.IsNil() {
				return berValueEqual
			}
			return berValueUnknown
		}
		if left.Type() == replayNodeType || left.Type() == replayStateType {
			if left.Pointer() == right.Pointer() {
				return berValueEqual
			}
			return berValueUnknown
		}
		if left.Type().Elem().Size() == 0 {
			// Go spec, Size and alignment guarantees: distinct zero-size
			// variables may share an address. The pointee has no value bits.
			return berValueEqual
		}
		if left.Pointer() == right.Pointer() {
			return berValueUnknown
		}
		return compareBERValueNodes(left.Elem(), right.Elem(), depth+1, nodeValues)
	case reflect.Interface:
		if left.IsNil() || right.IsNil() {
			if left.IsNil() == right.IsNil() {
				return berValueEqual
			}
			return berValueUnknown
		}
		return compareBERValueNodes(left.Elem(), right.Elem(), depth+1, nodeValues)
	case reflect.Slice, reflect.Array:
		if left.Len() != right.Len() {
			return berValueDifferent
		}
		if left.Kind() == reflect.Slice && left.Type().Elem().Kind() == reflect.Uint8 {
			return berComparison(bytes.Equal(left.Bytes(), right.Bytes()))
		}
		result := berValueEqual
		for index := 0; index < left.Len(); index++ {
			switch compareBERValueNodes(left.Index(index), right.Index(index), depth+1, nodeValues) {
			case berValueDifferent:
				return berValueDifferent
			case berValueUnknown:
				result = berValueUnknown
			}
		}
		return result
	case reflect.Struct:
		// Generated CHOICEs have an untagged Choice discriminator and a
		// replay-node field. Only the selected alternative is a value:
		// X.680 (02/2021) §29. An ordinary SEQUENCE component named Choice
		// has an asn1 tag and therefore does not meet this layout.
		selected := -1
		if plan.choice {
			leftChoice, rightChoice := int(left.Field(0).Int()), int(right.Field(0).Int())
			if plan.choiceExtension >= 0 && (leftChoice >= 1 || rightChoice >= 1) &&
				(!left.Field(plan.choiceExtension).IsNil() || !right.Field(plan.choiceExtension).IsNil()) {
				// X.680 (02/2021) §29.1; X.690 (02/2021) §8.13:
				// a CHOICE has one selected alternative. Defer a value
				// with both forms selected to encoder validation.
				return berValueUnknown
			}
			if leftChoice < 1 || rightChoice < 1 || leftChoice > len(plan.alternatives) || rightChoice > len(plan.alternatives) {
				return berValueUnknown
			}
			if leftChoice != rightChoice {
				return berValueDifferent
			}
			selected = plan.alternatives[leftChoice-1]
		}
		result := berValueEqual
		for _, field := range plan.fields {
			if selected >= 0 && field.index != selected && !field.replayNode {
				continue
			}
			if result == berValueDifferent && (nodeValues == nil || !field.containsReplay) {
				continue // No later value-only field can change a firm verdict.
			}
			leftField, rightField := left.Field(field.index), right.Field(field.index)
			if field.nilable && leftField.IsNil() && rightField.IsNil() {
				continue
			}
			var comparison berValueComparison
			if field.optional && berOptionalPresenceDiffers(leftField, rightField) {
				// Generated BER emits OPTIONAL and DEFAULT components exactly
				// when their fields are non-nil. X.690 (02/2021) §§8.9.3,
				// 8.11.3 permit either form for DEFAULT; §11.5 restricts CER/DER.
				comparison = berValueDifferent
			} else {
				switch {
				case field.byteSlice:
					comparison = berComparison(bytes.Equal(leftField.Bytes(), rightField.Bytes()))
				case field.quickKind == reflect.Bool:
					comparison = berComparison(leftField.Bool() == rightField.Bool())
				case field.quickKind >= reflect.Int && field.quickKind <= reflect.Int64:
					comparison = berComparison(leftField.Int() == rightField.Int())
				case field.quickKind >= reflect.Uint && field.quickKind <= reflect.Uintptr:
					comparison = berComparison(leftField.Uint() == rightField.Uint())
				case field.quickKind == reflect.String:
					comparison = berComparison(leftField.String() == rightField.String())
				default:
					// The generated SEQUENCE and SET encoders append ExtData_
					// TLVs verbatim (X.690 (02/2021) §§8.9.2, 8.11.2).
					comparison = compareBERValueNodes(leftField, rightField, depth+1, nodeValues)
				}
			}
			switch comparison {
			case berValueDifferent:
				if field.valueField || field.extData {
					result = berValueDifferent
					break
				}
				if result != berValueDifferent {
					result = berValueUnknown
				}
			case berValueUnknown:
				if result != berValueDifferent {
					result = berValueUnknown
				}
			}
		}
		if nodeValues != nil {
			for _, index := range plan.replayFields {
				field := left.Field(index)
				baselineField := right.Field(index)
				if !field.IsNil() && !baselineField.IsNil() && field.Pointer() == baselineField.Pointer() {
					nodeValues.put(field.Pointer(), result)
				}
			}
		}
		return result
	case reflect.Map:
		if left.Len() != right.Len() {
			return berValueDifferent
		}
		result := berValueEqual
		for iterator := left.MapRange(); iterator.Next(); {
			other := right.MapIndex(iterator.Key())
			if !other.IsValid() {
				return berValueDifferent
			}
			switch compareBERValueNodes(iterator.Value(), other, depth+1, nodeValues) {
			case berValueDifferent:
				return berValueDifferent
			case berValueUnknown:
				result = berValueUnknown
			}
		}
		return result
	case reflect.Func:
		if left.IsNil() && right.IsNil() {
			return berValueEqual
		}
		return berValueUnknown
	default:
		return berValueUnknown
	}
}

func berOptionalPresenceDiffers(left, right reflect.Value) bool {
	switch left.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		return left.IsNil() != right.IsNil()
	default:
		return false
	}
}

func berBitStringLengthFits(value runtime.BitString) bool {
	if value.BitLength < 0 {
		return false
	}
	full := value.BitLength / 8
	return full < len(value.Bytes) || full == len(value.Bytes) && value.BitLength%8 == 0
}

var bigIntType = reflect.TypeFor[big.Int]()

var externalType = reflect.TypeFor[runtime.External]()

var externalPointerType = reflect.TypeFor[*runtime.External]()

var realType = reflect.TypeFor[runtime.Real]()

var bitStringType = reflect.TypeFor[runtime.BitString]()

var rawValueType = reflect.TypeFor[runtime.RawValue]()

var objectIdentifierType = reflect.TypeFor[runtime.ObjectIdentifier]()

var relativeObjectIdentifierType = reflect.TypeFor[runtime.RelativeObjectIdentifier]()

var replayNodeType = reflect.TypeFor[*ReplayNode]()

var replayStateType = reflect.TypeFor[*ReplayState]()

func cloneBERReflect(value reflect.Value, seen map[reflect.Value]reflect.Value) (reflect.Value, error) {
	if !value.IsValid() {
		return value, nil
	}
	if value.Type() == replayNodeType || value.Type() == replayStateType {
		return value, nil
	}
	if value.Type() == bigIntType {
		copyValue := new(big.Int)
		original := value.Interface().(big.Int)
		copyValue.Set(&original)
		return reflect.ValueOf(*copyValue), nil
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() {
			return value, nil
		}
		if prior, ok := seen[value]; ok {
			return prior, nil
		}
		copyValue := reflect.New(value.Type().Elem())
		seen[value] = copyValue
		inner, err := cloneBERReflect(value.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		copyValue.Elem().Set(inner)
		return copyValue, nil
	case reflect.Interface:
		if value.IsNil() {
			return value, nil
		}
		inner, err := cloneBERReflect(value.Elem(), seen)
		if err != nil {
			return reflect.Value{}, err
		}
		copyValue := reflect.New(value.Type()).Elem()
		copyValue.Set(inner)
		return copyValue, nil
	case reflect.Struct:
		copyValue := reflect.New(value.Type()).Elem()
		copyValue.Set(value)
		for index := 0; index < value.NumField(); index++ {
			if !copyValue.Field(index).CanSet() || !value.Field(index).CanInterface() {
				continue
			}
			inner, err := cloneBERReflect(value.Field(index), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			copyValue.Field(index).Set(inner)
		}
		return copyValue, nil
	case reflect.Slice:
		if value.IsNil() {
			return value, nil
		}
		copyValue := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
		if value.Type().Elem().Kind() == reflect.Uint8 {
			reflect.Copy(copyValue, value)
			return copyValue, nil
		}
		for index := 0; index < value.Len(); index++ {
			inner, err := cloneBERReflect(value.Index(index), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			copyValue.Index(index).Set(inner)
		}
		return copyValue, nil
	case reflect.Array:
		copyValue := reflect.New(value.Type()).Elem()
		for index := 0; index < value.Len(); index++ {
			inner, err := cloneBERReflect(value.Index(index), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			copyValue.Index(index).Set(inner)
		}
		return copyValue, nil
	case reflect.Map:
		if value.IsNil() {
			return value, nil
		}
		copyValue := reflect.MakeMapWithSize(value.Type(), value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			inner, err := cloneBERReflect(iterator.Value(), seen)
			if err != nil {
				return reflect.Value{}, err
			}
			copyValue.SetMapIndex(iterator.Key(), inner)
		}
		return copyValue, nil
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return reflect.Value{}, fmt.Errorf("%w: unsupported BER replay value kind %s", ErrInvalidValue, value.Kind())
	default:
		return value, nil
	}
}
