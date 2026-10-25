// Code generated from X2AP runtime source. DO NOT EDIT.

// Runtime source: runtime/aper/replay.go; SHA-256 d1623c297ce77f34cb12598370de078cf51d7454674a0cfe86c7441f0cfa07f3.
package aper

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"unsafe"
)

// Snapshot identifies an exact source-shaped semantic subtree. It is neither
// a PER encoding nor a digest; mutable contents are retained independently.
type Snapshot struct {
	owner            *semanticArena
	start, end, node int
}
type semanticArena struct {
	data             []byte
	nodes            int
	original         []byte
	budget           DecodeBudget
	origin           originMap
	buffers          []BitBuffer
	nextBuffer       int
	scalars          []int64
	nextScalar       int
	report           DecodeReport
	spanSlots        []BitSpan
	nextSpan         int
	observationSlots []Observation
	failedBuffer     BitBuffer
}
type SemanticFrame struct {
	start, end, limit int
	changed           bool
}

// SemanticCapture records immutable semantics once after a successful decode.
// Its write-capable API is separate from comparison to keep encoding read-only.
type SemanticCapture struct {
	owner *semanticArena
}

func NewSemanticCapture(hint int) SemanticCapture {
	if hint < 256 {
		hint = 256
	}
	return SemanticCapture{owner: &semanticArena{data: make([]byte, 0, hint), budget: DecodeBudget{limits: defaultLegacyLimits()}}}
}
func (s *SemanticCapture) Begin() SemanticFrame {
	if s.Failed() {
		return SemanticFrame{start: -1}
	}
	f := SemanticFrame{start: len(s.owner.data)}
	var header [8]byte
	s.fixed(header[:])
	if s.Failed() {
		return SemanticFrame{start: -1}
	}
	return f
}
func (s *SemanticCapture) End(f SemanticFrame, node *Snapshot, _ bool) {
	if f.start < 0 || s.Failed() {
		return
	}
	binary.LittleEndian.PutUint64(s.owner.data[f.start:f.start+8], uint64(len(s.owner.data)-f.start-8))
	if node != nil {
		*node = Snapshot{owner: s.owner, start: f.start, end: len(s.owner.data), node: s.owner.nodes}
		s.owner.nodes++
	}
}
func (s *SemanticCapture) fixed(data []byte) {
	next, err := AppendValues(NewBudgetBuffer(&s.owner.budget), s.owner.data, data...)
	if err != nil {
		return
	}
	s.owner.data = next
}
func (s *SemanticCapture) Uint(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	s.fixed(data[:])
}

// Int preserves the complete signed value as its unique 64-bit representation.
func (s *SemanticCapture) Int(value int64) { s.Uint(uint64(value)) }
func (s *SemanticCapture) Bool(value bool) {
	var data [1]byte
	if value {
		data[0] = 1
	}
	s.fixed(data[:])
}
func (s *SemanticCapture) Bytes(value []byte) {
	s.Uint(uint64(len(value)))
	s.fixed(value)
}

// semanticBits excludes backing storage outside the declared value. X.691
// (02/2021) §§16.4–16.5 define the value as exactly bitLength significant bits.
// Invalid short storage stays distinct from every valid decoded baseline.
func semanticBits(value []byte, bitLength int) ([]byte, byte, bool) {
	if bitLength < 0 {
		return value, 0, false
	}
	whole, remainder := bitLength/8, bitLength%8
	if whole > len(value) || remainder != 0 && whole == len(value) {
		return value, 0, false
	}
	if remainder == 0 {
		return value[:whole], 0, false
	}
	return value[:whole], value[whole] & byte(0xff<<uint(8-remainder)), true
}

func (s *SemanticCapture) BitString(value []byte, bitLength int) {
	s.Int(int64(bitLength))
	prefix, tail, hasTail := semanticBits(value, bitLength)
	n := len(prefix)
	if hasTail {
		n++
	}
	s.Uint(uint64(n))
	s.fixed(prefix)
	if hasTail {
		last := [1]byte{tail}
		s.fixed(last[:])
	}
}
func (s *SemanticCapture) String(value string) {
	s.Uint(uint64(len(value)))
	s.fixed([]byte(value))
}
func (s *SemanticCapture) BigInt(value *big.Int) {
	s.Bool(value == nil)
	if value == nil {
		return
	}
	s.Uint(uint64(int64(value.Sign())))
	s.Uint(uint64(len(value.Bits())))
	for _, word := range value.Bits() {
		if s.Failed() {
			break
		}
		s.Uint(uint64(word))
	}
}
func (s *SemanticCapture) Opaque(value OpaqueOpenType) {
	s.OpenLength(uint64(value.contentLength()))
	if !value.image.Present() {
		s.Bytes(value.bytes)
		return
	}
	s.Uint(uint64(value.image.Len()))
	if len(value.image.segments) == 0 {
		s.fixed(value.image.original[value.image.start/8 : value.image.end/8])
		return
	}
	for _, p := range value.image.segments {
		s.fixed(value.image.original[p.Start/8 : p.End/8])
	}
}
func (s *SemanticCapture) ChoiceExtension(value *ChoiceExtension) {
	s.Bool(value == nil)
	if value != nil {
		s.Uint(uint64(value.index))
		s.Opaque(OpaqueOpenType{bytes: value.contents, image: value.image})
	}
}

// ReplayPlan is a by-value decision result. Its inline states never point back
// into a caller's stack, so an unchanged encode needs only its returned bytes.
// Large trees use one bounded overflow slice; no state is retained in values.
type ReplayPlan struct {
	root   Snapshot
	states [64]uint8
	extra  []uint8
	budget DecodeBudget
}

// A settled tree defaults to unchanged. Only changed node IDs need storage;
// large-tree overflow is allocated lazily after a change has been established.
// This keeps an unchanged value at one result allocation at every tree size.
func (p *ReplayPlan) markChanged(node int) {
	if node < 0 || p.root.owner == nil || node >= p.root.owner.nodes {
		return
	}
	// A semantic edit after tolerated padding requests canonical padding throughout
	// the known value tree (X.691 (02/2021) §§11.1.4, 11.2.1). The negative node
	// belongs only to this plan; the immutable received snapshot is unchanged.
	if p.root.owner.budget.nonzeroTerminalPadding && len(p.root.owner.buffers) > 0 {
		trace := p.root.owner.buffers[0].trace
		if trace != nil && trace.nonzeroPadding {
			p.root.node = -1
			return
		}
	}

	index := node / 8
	mask := uint8(1) << uint(node%8)
	if index < len(p.states) {
		p.states[index] |= mask
		return
	}
	if p.extra == nil {
		count := (p.root.owner.nodes-1)/8 + 1 - len(p.states)
		if err := NewBudgetBuffer(&p.budget).ChargeAllocation(uint64(count), 1); err != nil {
			return
		}
		p.extra = make([]uint8, count)
	}
	p.extra[index-len(p.states)] |= mask
}
func (p *ReplayPlan) Unchanged(node Snapshot) bool {
	if p == nil || p.root.node < 0 || node.owner == nil || node.owner != p.root.owner || node.node < 0 || node.node >= node.owner.nodes {
		return false
	}
	index := node.node / 8
	mask := uint8(1) << uint(node.node%8)
	if index < len(p.states) {
		return p.states[index]&mask == 0
	}
	return len(p.extra) == 0 || p.extra[index-len(p.states)]&mask == 0
}

func (s Snapshot) Present() bool { return s.owner != nil }

// SemanticComparison reads the baseline and settles each occurrence in one
// postorder traversal, independently of the write-capable capture API.
type SemanticComparison struct {
	plan       ReplayPlan
	pos, limit int
	changed    bool
}

func NewSemanticComparison(root Snapshot, budgets ...DecodeBudget) SemanticComparison {
	budget := DecodeBudget{limits: defaultLegacyLimits()}
	if len(budgets) > 0 {
		budget = budgets[0]
	}
	s := SemanticComparison{plan: ReplayPlan{root: root, budget: budget}, pos: root.start, limit: root.end}

	return s
}
func (s *SemanticComparison) Plan() ReplayPlan { return s.plan }
func (s *SemanticComparison) Begin() SemanticFrame {
	if err := NewBudgetBuffer(&s.plan.budget).ChargeWork(1); err != nil {
		s.changed = true
	}
	f := SemanticFrame{start: s.pos, end: s.limit, limit: s.limit, changed: s.changed}
	s.changed = false
	if s.pos <= s.limit-8 {
		n := binary.LittleEndian.Uint64(s.plan.root.owner.data[s.pos : s.pos+8])
		s.pos += 8
		if n <= uint64(s.limit-s.pos) {
			f.end = s.pos + int(n)
		} else {
			s.changed = true
		}
	} else {
		s.changed = true
	}
	s.limit = f.end
	return f
}
func (s *SemanticComparison) End(f SemanticFrame, node Snapshot, fresh bool) {
	if s.pos != f.end || fresh {
		s.changed = true
	}
	if node.owner != nil && node.owner == s.plan.root.owner {
		dirty := s.changed || node.start != f.start || node.end != f.end
		if dirty {
			s.plan.markChanged(node.node)
		}
	}
	s.changed = s.changed || f.changed
	s.pos, s.limit = f.end, f.limit
}
func (s *SemanticComparison) fixed(data []byte) {
	if err := NewBudgetBuffer(&s.plan.budget).ChargeWork(uint64(len(data))); err != nil {
		s.changed = true
		return
	}
	if len(data) > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	if !bytes.Equal(data, s.plan.root.owner.data[s.pos:s.pos+len(data)]) {
		s.changed = true
	}
	s.pos += len(data)
}
func (s *SemanticComparison) Uint(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	s.fixed(data[:])
}
func (s *SemanticComparison) Int(value int64) { s.Uint(uint64(value)) }
func (s *SemanticComparison) Bool(value bool) {
	var data [1]byte
	if value {
		data[0] = 1
	}
	s.fixed(data[:])
}
func (s *SemanticComparison) length() int {
	if s.pos > s.limit-8 {
		s.changed = true
		s.pos = s.limit
		return -1
	}
	n := binary.LittleEndian.Uint64(s.plan.root.owner.data[s.pos : s.pos+8])
	s.pos += 8
	if n > uint64(^uint(0)>>1) {
		s.changed = true
		return -1
	}
	return int(n)
}
func (s *SemanticComparison) Bytes(value []byte) {
	if err := NewBudgetBuffer(&s.plan.budget).ChargeWork(uint64(len(value))); err != nil {
		s.changed = true
		return
	}
	n := s.length()
	if n != len(value) {
		s.changed = true
	}
	if n < 0 || n > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	if !bytes.Equal(value, s.plan.root.owner.data[s.pos:s.pos+n]) {
		s.changed = true
	}
	s.pos += n
}

func (s *SemanticComparison) BitString(value []byte, bitLength int) {
	s.Int(int64(bitLength))
	prefix, tail, hasTail := semanticBits(value, bitLength)
	n := len(prefix)
	if hasTail {
		n++
	}
	s.Uint(uint64(n))
	s.fixed(prefix)
	if hasTail {
		last := [1]byte{tail}
		s.fixed(last[:])
	}
}
func (s *SemanticComparison) String(value string) {
	if err := NewBudgetBuffer(&s.plan.budget).ChargeWork(uint64(len(value))); err != nil {
		s.changed = true
		return
	}
	n := s.length()
	if n < 0 || n > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	if value != string(s.plan.root.owner.data[s.pos:s.pos+n]) {
		s.changed = true
	}
	s.pos += n
}
func (s *SemanticComparison) BigInt(value *big.Int) {
	s.Bool(value == nil)
	if value == nil {
		return
	}
	s.Uint(uint64(int64(value.Sign())))
	s.Uint(uint64(len(value.Bits())))
	for _, word := range value.Bits() {
		if s.Failed() {
			break
		}
		s.Uint(uint64(word))
	}
}
func (s *SemanticComparison) Opaque(value OpaqueOpenType) {
	s.OpenLength(uint64(value.contentLength()))
	if !value.image.Present() {
		s.Bytes(value.bytes)
		return
	}
	n := s.length()
	if n != value.image.Len() {
		s.changed = true
	}
	if n < 0 || n > s.limit-s.pos {
		s.changed = true
		s.pos = s.limit
		return
	}
	end := s.pos + n
	if len(value.image.segments) == 0 {
		s.fixed(value.image.original[value.image.start/8 : value.image.end/8])
	} else {
		for _, p := range value.image.segments {
			s.fixed(value.image.original[p.Start/8 : p.End/8])
		}
	}
	s.pos = end
}
func (s *SemanticComparison) ChoiceExtension(value *ChoiceExtension) {
	s.Bool(value == nil)
	if value != nil {
		s.Uint(uint64(value.index))
		s.Opaque(OpaqueOpenType{bytes: value.contents, image: value.image})
	}
}

func (bb *BitBuffer) ReplayPlan() *ReplayPlan {
	if bb.budget == nil {
		return nil
	}
	return bb.budget.encodePlan
}

// newSemanticOwner packs the original, small snapshots, scalar arms and decoder
// state into a single lifetime. Larger content grows only the corresponding
// bounded backing slice, never an enclosing wire copy.
type smallDecodeOwner struct {
	arena        semanticArena
	original     [8]byte
	semantics    [128]byte
	buffers      [1]BitBuffer
	scalars      [1]int64
	spans        [8]BitSpan
	observations [1]Observation
}

// The 19-octet capture family has four readers and 352 snapshot octets.
// Its 29 larger variants need 484 octets; 512 avoids their arena spill.
// The next family fits eight readers and usually 1,024 snapshot octets.
// Large messages use up to eleven readers and four mutable scalar arms.
// Capacities are calibrated from the complete X2AP corpus, not another schema.
type compactDecodeOwner struct {
	arena     semanticArena
	original  [32]byte
	semantics [512]byte
	buffers   [4]BitBuffer
	scalars   [1]int64
	spans     [8]BitSpan
}
type mediumDecodeOwner struct {
	arena     semanticArena
	original  [128]byte
	semantics [1024]byte
	buffers   [8]BitBuffer
	scalars   [4]int64
	spans     [12]BitSpan
}
type messageDecodeOwner struct {
	arena        semanticArena
	semantics    [4096]byte
	buffers      [12]BitBuffer
	scalars      [4]int64
	spans        [24]BitSpan
	observations [1]Observation
}

func newSemanticOwner(data []byte) *semanticArena {
	var owner *semanticArena
	switch {
	case len(data) <= 8:
		p := new(smallDecodeOwner)
		owner = &p.arena
		owner.original = p.original[:len(data)]
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
		owner.spanSlots = p.spans[:]
		owner.observationSlots = p.observations[:]
	case len(data) <= 32:
		p := new(compactDecodeOwner)
		owner = &p.arena
		owner.original = p.original[:len(data)]
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
		owner.spanSlots = p.spans[:]
	case len(data) <= 128:
		p := new(mediumDecodeOwner)
		owner = &p.arena
		owner.original = p.original[:len(data)]
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
		owner.spanSlots = p.spans[:]
	default:
		p := new(messageDecodeOwner)
		owner = &p.arena
		owner.original = make([]byte, len(data))
		owner.data = p.semantics[:0]
		owner.buffers = p.buffers[:]
		owner.scalars = p.scalars[:]
		owner.spanSlots = p.spans[:]
		owner.observationSlots = p.observations[:]
	}
	copy(owner.original, data)
	owner.budget.owner = owner
	owner.budget.origin = &owner.origin
	return owner
}

func NewCompleteDecodeBuffer(data []byte, options DecodeState) *BitBuffer {
	if options.settings.operation == nil || options.settings.operation.owner == nil {
		return NewBitBufferFromBytes(data)
	}
	return options.settings.operation.owner.buffer(data, nil)
}

// NewOwnedNestedDecodeBuffer supplies reader storage from a complete decode's
// owner. The separate low-level factory keeps caller-owned budgets on the stack.
func NewOwnedNestedDecodeBuffer(data []byte, parent *BitBuffer) *BitBuffer {
	if owner := parent.decodeBudget().owner; owner != nil {
		return owner.buffer(data, parent)
	}
	return NewNestedDecodeBuffer(data, parent)
}
func (o *semanticArena) buffer(data []byte, parent *BitBuffer) *BitBuffer {
	var bb *BitBuffer
	index := o.nextBuffer
	o.nextBuffer++
	if index < len(o.buffers) {
		bb = &o.buffers[index]
	} else {
		if err := ChargeValue(NewBudgetBuffer(&o.budget), BitBuffer{}); err != nil {
			bb = &o.failedBuffer
		} else {
			bb = new(BitBuffer)
		}
	}
	*bb = BitBuffer{data: data, budget: &o.budget, sourceReader: true, ownedInput: parent == nil || parent.ownsInput()}
	if len(data) > int(^uint(0)>>1)/8 {
		bb.invalidLength = true
	} else {
		bb.bitLen = len(data) * 8
	}
	if parent != nil {
		bb.nested = true
		bb.trace = parent.trace
		bb.sourceReader = parent.sourceReader
	}
	return bb
}
func SemanticCaptureFor(options DecodeState) SemanticCapture {
	if options.settings.operation == nil || options.settings.operation.owner == nil {
		return NewSemanticCapture(256)
	}
	return SemanticCapture{owner: options.settings.operation.owner}
}
func (bb *BitBuffer) ownsInput() bool {
	return bb.ownedInput && bb.sourceReader && bb.budget != nil && bb.budget.owner != nil
}

// OwnInt64 supplies mutable source scalar storage from the decode's owner.
// After its small inline capacity, each additional scalar has its own storage.
func (bb *BitBuffer) OwnInt64(value int64) *int64 {
	if bb.ownsInput() {
		o := bb.budget.owner
		index := o.nextScalar
		o.nextScalar++
		if index < len(o.scalars) {
			p := &o.scalars[index]
			*p = value
			return p
		}
	}
	if bb.ownsInput() {
		if err := bb.ChargeAllocation(1, 8); err != nil {
			return &bb.budget.owner.scalars[0]
		}
	}
	p := new(int64)
	*p = value
	return p
}

// ExtensionData observes effective unknown contents independently of whether
// they came from a caller's mutable setter or an immutable received span.
func (s *SemanticCapture) ExtensionData(data [][]byte, spans []WireSpan) {
	f := s.Begin()
	n := max(len(data), len(spans))
	for i := range n {
		if i < len(data) && data[i] != nil {
			s.Uint(uint64(i))
			s.Bytes(data[i])
		} else if i < len(spans) && spans[i].Present() {
			s.Uint(uint64(i))
			s.Opaque(OpaqueOpenType{image: spans[i]})
		}
	}
	s.End(f, nil, false)
}
func (s *SemanticComparison) ExtensionData(data [][]byte, spans []WireSpan) {
	f := s.Begin()
	n := max(len(data), len(spans))
	for i := range n {
		if i < len(data) && data[i] != nil {
			s.Uint(uint64(i))
			s.Bytes(data[i])
		} else if i < len(spans) && spans[i].Present() {
			s.Uint(uint64(i))
			s.Opaque(OpaqueOpenType{image: spans[i]})
		}
	}
	s.End(f, Snapshot{}, false)
}

// SuspendReplayPlan bounds an explicit fresh request to its subtree. Sibling
// nodes can still use the settled plan after the private encoder returns.
func (bb *BitBuffer) SuspendReplayPlan() *ReplayPlan {
	if bb.budget == nil {
		return nil
	}
	previous := bb.budget.encodePlan
	bb.budget.encodePlan = nil
	return previous
}
func (bb *BitBuffer) RestoreReplayPlan(previous *ReplayPlan) {
	if bb.budget != nil {
		bb.budget.encodePlan = previous
	}
}

func (bb *BitBuffer) SetReplayPlan(plan *ReplayPlan) { bb.decodeBudget().encodePlan = plan }

// Capture charges its independent semantic storage to the existing decode.
func (s *SemanticCapture) Failed() bool    { return s.owner == nil || s.owner.budget.err != nil }
func (s *SemanticComparison) Failed() bool { return s.plan.budget.err != nil }
func (s *SemanticCapture) EnterValue()     {}
func (s *SemanticCapture) LeaveValue()     {}
func (s *SemanticComparison) EnterValue() {
	if err := NewBudgetBuffer(&s.plan.budget).EnterDecodeValue(); err != nil {
		s.changed = true
	}
}
func (s *SemanticComparison) LeaveValue()    { NewBudgetBuffer(&s.plan.budget).LeaveDecodeValue() }
func (s *SemanticCapture) Elements(_ uint64) {}
func (s *SemanticComparison) Elements(n uint64) {
	if n > uint64(^uint(0)>>1) {
		s.plan.budget.err = ErrLimit
		return
	}
	if err := NewBudgetBuffer(&s.plan.budget).ChargeElements(int64(n)); err != nil {
		s.changed = true
	}
}

// Open metadata is observational framing, excluded from semantic equality.
// It reserves the received form examined as a replay candidate without encoding.
func (s *SemanticCapture) Open(image WireSpan) { s.Uint(uint64(image.Len())) }
func (s *SemanticComparison) Open(image WireSpan) {
	n := s.length()
	if n < 0 {
		return
	}
	s.OpenLength(max(uint64(n), uint64(image.Len())))
}
func (s *SemanticCapture) OpenLength(_ uint64) {}
func (s *SemanticComparison) OpenLength(n uint64) {
	if err := NewBudgetBuffer(&s.plan.budget).ChargeOpenTypeFraming(n); err != nil {
		s.changed = true
	}
}

// CommitBudget publishes only this encode's counters; decoded state is immutable.
func (p ReplayPlan) CommitBudget(budget *DecodeBudget) error { *budget = p.budget; return budget.err }

func (p ReplayPlan) Error() error                 { return p.budget.err }
func (p ReplayPlan) EncodingBudget() DecodeBudget { return p.budget }

// ownerFootprint is the fixed storage already reserved by this decode.
func ownerFootprint(octets int) uint64 {
	switch {
	case octets <= 8:
		return uint64(unsafe.Sizeof(smallDecodeOwner{}))
	case octets <= 32:
		return uint64(unsafe.Sizeof(compactDecodeOwner{}))
	case octets <= 128:
		return uint64(unsafe.Sizeof(mediumDecodeOwner{}))
	default:
		return uint64(unsafe.Sizeof(messageDecodeOwner{}))
	}
}

// captureSpans supplies independent metadata slots during one decode. Every
// returned slice has its own range and capacity; report edits cannot reach a
// decoded value's location or a later slot.
func (bb *BitBuffer) captureSpans(spans []BitSpan) []BitSpan {
	if owner := bb.decodeBudget().owner; owner != nil && len(spans) <= len(owner.spanSlots)-owner.nextSpan {
		if err := bb.ChargeWork(uint64(len(spans)) * 16); err != nil {
			return nil
		}
		start := owner.nextSpan
		owner.nextSpan += len(spans)
		out := owner.spanSlots[start:owner.nextSpan:owner.nextSpan]
		copy(out, spans)
		return out
	}
	if err := bb.ChargeAllocation(uint64(len(spans)), 16); err != nil {
		return nil
	}
	return append([]BitSpan(nil), spans...)
}
func (bb *BitBuffer) captureSpanLocation(image WireSpan) Location {
	if !image.Present() {
		return Location{}
	}
	spans := image.segments
	var first [1]BitSpan
	if len(spans) == 0 {
		first[0] = BitSpan{Start: image.start, End: image.end}
		spans = first[:]
	}
	return Location{Spans: bb.captureSpans(spans), HasWireLocation: true}
}
